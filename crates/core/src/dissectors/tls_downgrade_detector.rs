use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pair_correlation::FiveTuple;
    use crate::pqc_handshake::{KemId, PqcHandshakeRecord, PqcKem, SigAlgorithm, TlsVersion};
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
        success: bool,
        kem: Option<KemId>,
        hybrid: bool,
        fallback: Option<&str>,
        name: &str,
    ) -> PqcHandshakeRecord {
        let mut r = PqcHandshakeRecord::new(
            test_ft(),
            TlsVersion::TlsV1_3,
            name.into(),
            SigAlgorithm::RsaPkcs1Sha256,
            Utc::now(),
        );
        r.is_success = success;
        r.is_hybrid_kem = hybrid;
        r.pqc_fallback_reason = fallback.map(String::from);
        if let Some(k) = kem {
            r.pqc_kem = Some(PqcKem {
                algorithm: k,
                public_key: None,
                ciphertext: None,
                shared_secret: None,
            });
        }
        r
    }

    #[test]
    fn detect_version_downgrade_clean() {
        let r = make_record(true, Some(KemId::MlKem768), false, None, "example.com");
        let findings = detect_version_downgrade(&[r]);
        assert!(findings.is_empty());
    }

    #[test]
    fn detect_version_downgrade_fallback_reason() {
        let r = make_record(
            true,
            Some(KemId::MlKem768),
            false,
            Some("TLS 1.2 fallback"),
            "example.com",
        );
        let findings = detect_version_downgrade(&[r]);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].contains("example.com"));
        assert!(findings[0].contains("TLS 1.2 fallback"));
    }

    #[test]
    fn detect_version_downgrade_failed_pqc() {
        let r = make_record(false, Some(KemId::MlKem768), false, None, "example.com");
        let findings = detect_version_downgrade(&[r]);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].contains("PQC KEM offered but handshake failed"));
    }

    #[test]
    fn detect_hybrid_stripping_empty() {
        let r = make_record(true, Some(KemId::MlKem768), false, None, "example.com");
        let findings = detect_hybrid_stripping(&[r]);
        assert!(findings.is_empty());
    }

    #[test]
    fn detect_hybrid_stripping_detected() {
        let r = make_record(false, Some(KemId::MlKem768), true, None, "hybrid.example");
        let findings = detect_hybrid_stripping(&[r]);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].contains("hybrid KEM advertised but negotiation failed"));
    }

    #[test]
    fn dissect_clean() {
        crate::dissectors::tls::clear_tls_sessions();
        let result = dissect_tls_downgrade_detector(None, None, 443, 54321, &[]);
        assert_eq!(result.protocol, Protocol::TlsDowngradeDetector);
        assert!(result.summary.contains("no downgrade detected"));
    }

    #[test]
    fn dissect_with_findings() {
        crate::dissectors::tls::clear_tls_sessions();
        let r = make_record(
            false,
            Some(KemId::MlKem768),
            true,
            Some("downgrade to 1.2"),
            "bad.example",
        );
        crate::dissectors::tls::push_pqc_record_for_test(r);
        let result = dissect_tls_downgrade_detector(None, None, 443, 54321, &[]);
        assert!(result.summary.contains("alerts"));
        assert!(result.summary.contains("bad.example"));
    }
}

fn detect_version_downgrade(records: &[crate::pqc_handshake::PqcHandshakeRecord]) -> Vec<String> {
    let mut findings = Vec::new();
    for r in records {
        if let Some(ref reason) = r.pqc_fallback_reason {
            if reason.contains("downgrade") || reason.contains("fallback") || reason.contains("1.2")
            {
                findings.push(format!("{}: {}", r.server_name, reason,));
            }
        }
        if !r.is_success && r.pqc_kem.is_some() {
            findings.push(format!(
                "{}: PQC KEM offered but handshake failed",
                r.server_name,
            ));
        }
    }
    findings
}

fn detect_hybrid_stripping(records: &[crate::pqc_handshake::PqcHandshakeRecord]) -> Vec<String> {
    records
        .iter()
        .filter(|r| r.pqc_kem.is_some() && !r.is_success && r.is_hybrid_kem)
        .map(|r| {
            format!(
                "{}: hybrid KEM advertised but negotiation failed",
                r.server_name,
            )
        })
        .collect()
}

pub fn dissect_tls_downgrade_detector(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    _payload: &[u8],
) -> DissectedResult {
    let records = crate::dissectors::tls::drain_pqc_store();

    let downgrade_findings = detect_version_downgrade(&records);
    let stripping_findings = detect_hybrid_stripping(&records);
    let total_findings = downgrade_findings.len() + stripping_findings.len();

    let summary = if total_findings > 0 {
        let mut parts = Vec::new();
        if !downgrade_findings.is_empty() {
            parts.push(format!("downgrade: {}", downgrade_findings.join("; ")));
        }
        if !stripping_findings.is_empty() {
            parts.push(format!("hybrid-strip: {}", stripping_findings.join("; ")));
        }
        format!(
            "TLS Downgrade Detector: {} alerts — {}",
            total_findings,
            parts.join(" | "),
        )
    } else {
        format!(
            "TLS Downgrade Detector: no downgrade detected ({} sessions analyzed)",
            records.len(),
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TlsDowngradeDetector,
        summary,
    }
}
