use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pair_correlation::FiveTuple;
    use crate::pqc_handshake::{PqcHandshakeRecord, TlsVersion, SigAlgorithm, KemId, PqcKem};
    use chrono::Utc;

    fn test_ft() -> FiveTuple {
        FiveTuple {
            src_ip: "10.0.0.1".parse().unwrap(),
            src_port: 54321,
            dst_ip: "93.184.216.34".parse().unwrap(),
            dst_port: 443,
            protocol: 6,
        }
    }

    fn make_record(
        name: &str, ch_size: u16, sh_size: u16, cert_len: u8,
        success: bool, hybrid: bool, kem: Option<KemId>,
    ) -> PqcHandshakeRecord {
        let mut r = PqcHandshakeRecord::new(
            test_ft(), TlsVersion::TlsV1_3, name.into(),
            SigAlgorithm::RsaPkcs1Sha256, Utc::now(),
        );
        r.client_hello_size = ch_size;
        r.server_hello_size = sh_size;
        r.cert_chain_length = cert_len;
        r.is_success = success;
        r.is_hybrid_kem = hybrid;
        if let Some(k) = kem {
            r.pqc_kem = Some(PqcKem { algorithm: k, public_key: None, ciphertext: None, shared_secret: None });
        }
        r
    }

    #[test]
    fn detect_abnormal_sizes_clean() {
        let r = make_record("example.com", 500, 500, 3, true, false, None);
        let findings = detect_abnormal_sizes(&[r]);
        assert!(findings.is_empty());
    }

    #[test]
    fn detect_abnormal_sizes_oversized_ch() {
        let r = make_record("example.com", 3000, 500, 3, true, false, None);
        let findings = detect_abnormal_sizes(&[r]);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].contains("oversized ClientHello"));
    }

    #[test]
    fn detect_abnormal_sizes_oversized_sh() {
        let r = make_record("example.com", 500, 3000, 3, true, false, None);
        let findings = detect_abnormal_sizes(&[r]);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].contains("oversized ServerHello"));
    }

    #[test]
    fn detect_abnormal_sizes_deep_chain() {
        let r = make_record("example.com", 500, 500, 8, true, false, None);
        let findings = detect_abnormal_sizes(&[r]);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].contains("deep cert chain"));
    }

    #[test]
    fn detect_protocol_anomalies_clean() {
        let r = make_record("example.com", 500, 500, 3, true, false, Some(KemId::MlKem768));
        let findings = detect_protocol_anomalies(&[r]);
        assert!(findings.is_empty());
    }

    #[test]
    fn detect_protocol_anomalies_rejected_pqc() {
        let r = make_record("example.com", 500, 500, 3, false, false, Some(KemId::MlKem768));
        let findings = detect_protocol_anomalies(&[r]);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].contains("possible middlebox"));
    }

    #[test]
    fn detect_protocol_anomalies_stripped_hybrid() {
        let r = make_record("example.com", 500, 500, 3, false, true, Some(KemId::MlKem768));
        let findings = detect_protocol_anomalies(&[r]);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn dissect_clean() {
        crate::dissectors::tls::clear_tls_sessions();
        let result = dissect_tls_middlebox_detector(None, None, 443, 54321, &[]);
        assert_eq!(result.protocol, Protocol::TlsMiddleboxDetector);
        assert!(result.summary.contains("no interference detected"));
    }

    #[test]
    fn dissect_with_anomalies() {
        crate::dissectors::tls::clear_tls_sessions();
        let r = make_record("bad.example", 3000, 500, 3, false, true, Some(KemId::MlKem768));
        crate::dissectors::tls::push_pqc_record_for_test(r);
        let result = dissect_tls_middlebox_detector(None, None, 443, 54321, &[]);
        assert!(result.summary.contains("anomalies"));
        assert!(result.summary.contains("bad.example"));
    }
}

fn detect_abnormal_sizes(records: &[crate::pqc_handshake::PqcHandshakeRecord]) -> Vec<String> {
    let mut findings = Vec::new();
    for r in records {
        if r.client_hello_size > 2048 {
            findings.push(format!(
                "{}: oversized ClientHello ({}B)",
                r.server_name, r.client_hello_size,
            ));
        }
        if r.server_hello_size > 2048 && r.server_hello_size > 0 {
            findings.push(format!(
                "{}: oversized ServerHello ({}B)",
                r.server_name, r.server_hello_size,
            ));
        }
        if r.cert_chain_length > 5 {
            findings.push(format!(
                "{}: deep cert chain ({} certs)",
                r.server_name, r.cert_chain_length,
            ));
        }
    }
    findings
}

fn detect_protocol_anomalies(records: &[crate::pqc_handshake::PqcHandshakeRecord]) -> Vec<String> {
    let mut findings = Vec::new();
    for r in records {
        if r.tls_version.as_u16() == 0x0304 && !r.is_success && r.pqc_kem.is_some() {
            findings.push(format!(
                "{}: TLS 1.3 PQC rejected — possible middlebox",
                r.server_name,
            ));
        }
        if r.is_hybrid_kem && !r.is_success {
            findings.push(format!(
                "{}: hybrid KEM stripped — middlebox interference",
                r.server_name,
            ));
        }
    }
    findings
}

pub fn dissect_tls_middlebox_detector(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    _payload: &[u8],
) -> DissectedResult {
    let records = crate::dissectors::tls::drain_pqc_store();
    let size_findings = detect_abnormal_sizes(&records);
    let proto_findings = detect_protocol_anomalies(&records);
    let total = size_findings.len() + proto_findings.len();

    let summary = if total > 0 {
        let mut parts = Vec::new();
        if !size_findings.is_empty() {
            parts.push(format!("size: {}", size_findings.join("; ")));
        }
        if !proto_findings.is_empty() {
            parts.push(format!("proto: {}", proto_findings.join("; ")));
        }
        format!(
            "TLS Middlebox Detector: {} anomalies — {}",
            total,
            parts.join(" | "),
        )
    } else {
        format!(
            "TLS Middlebox Detector: no interference detected ({} sessions)",
            records.len(),
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TlsMiddleboxDetector,
        summary,
    }
}
