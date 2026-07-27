use std::net::IpAddr;

use crate::models::Protocol;
use crate::pqc_handshake;
use crate::pqc_wizard::Tls13PqcWizard;

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

    fn make_record(name: &str, success: bool, pqc: bool, hybrid: bool) -> PqcHandshakeRecord {
        let mut r = PqcHandshakeRecord::new(
            test_ft(), TlsVersion::TlsV1_3, name.into(),
            if pqc { SigAlgorithm::MlDsa65 } else { SigAlgorithm::RsaPkcs1Sha256 },
            Utc::now(),
        );
        r.is_success = success;
        r.is_hybrid_kem = hybrid;
        if pqc {
            r.pqc_kem = Some(PqcKem { algorithm: KemId::MlKem768, public_key: None, ciphertext: None, shared_secret: None });
            r.server_kem_selected = Some(KemId::MlKem768);
        }
        r
    }

    #[test]
    fn dissect_empty_store() {
        crate::dissectors::tls::clear_tls_sessions();
        let result = dissect_tls_pqc_wizard_scan(None, None, 0, 0, &[]);
        assert_eq!(result.protocol, Protocol::TlsPqcWizardScan);
        assert!(result.summary.contains("0 handshakes"));
    }

    #[test]
    fn dissect_with_records() {
        crate::dissectors::tls::clear_tls_sessions();
        let r1 = make_record("a.example", true, true, false);
        let r2 = make_record("b.example", true, false, false);
        crate::dissectors::tls::push_pqc_record_for_test(r1);
        crate::dissectors::tls::push_pqc_record_for_test(r2);
        let result = dissect_tls_pqc_wizard_scan(None, None, 443, 54321, &[]);
        assert!(result.summary.contains("2 handshakes"));
        assert!(result.src_port == Some(443));
        assert!(result.dst_port == Some(54321));
    }
}

pub fn dissect_tls_pqc_wizard_scan(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    _payload: &[u8],
) -> DissectedResult {
    let store = {
        let records = crate::dissectors::tls::drain_pqc_store();
        let mut s = pqc_handshake::PqcHandshakeStore::new();
        for r in records {
            s.push(r);
        }
        s
    };
    let report = Tls13PqcWizard::analyze(&store);

    let vuln_count = report.vulnerabilities.len();
    let rec_count = report.recommendations.len();
    let comp_count = report.compliance.len();
    let risk = report.overview.risk_score.label();
    let adoption = report.overview.adoption_rate;

    let summary = format!(
        "TLS PQC Wizard Scan: {} handshakes, adoption {:.1}%, risk {}, {} vulnerabilities, {} recommendations, {} compliance flags",
        report.raw_records, adoption, risk, vuln_count, rec_count, comp_count,
    );
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TlsPqcWizardScan,
        summary,
    }
}
