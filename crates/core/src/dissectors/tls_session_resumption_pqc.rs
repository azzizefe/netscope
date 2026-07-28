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

    fn make_record(is_0rtt: bool, pqc: bool) -> PqcHandshakeRecord {
        let mut r = PqcHandshakeRecord::new(
            test_ft(),
            TlsVersion::TlsV1_3,
            "example.com".into(),
            if pqc {
                SigAlgorithm::MlDsa65
            } else {
                SigAlgorithm::RsaPkcs1Sha256
            },
            Utc::now(),
        );
        r.is_0rtt = is_0rtt;
        if pqc {
            r.pqc_kem = Some(PqcKem {
                algorithm: KemId::MlKem768,
                public_key: None,
                ciphertext: None,
                shared_secret: None,
            });
            r.server_kem_selected = Some(KemId::MlKem768);
        }
        r
    }

    #[test]
    fn analyze_resumption_empty() {
        let (total, pqc, ratio) = analyze_resumption(&[]);
        assert_eq!(total, 0);
        assert_eq!(pqc, 0);
        assert_eq!(ratio, 0.0);
    }

    #[test]
    fn analyze_resumption_no_psk() {
        let records = vec![make_record(false, true), make_record(false, false)];
        let (total, pqc, ratio) = analyze_resumption(&records);
        assert_eq!(total, 0);
        assert_eq!(pqc, 0);
        assert_eq!(ratio, 0.0);
    }

    #[test]
    fn analyze_resumption_with_psk() {
        let records = vec![
            make_record(true, true),  // PQC + 0-RTT
            make_record(true, false), // classic + 0-RTT
            make_record(false, true), // PQC no 0-RTT
        ];
        let (total, pqc, ratio) = analyze_resumption(&records);
        assert_eq!(total, 2);
        assert_eq!(pqc, 1);
        assert!((ratio - 50.0).abs() < 0.01);
    }

    #[test]
    fn analyze_resumption_all_pqc_psk() {
        let records = vec![make_record(true, true), make_record(true, true)];
        let (total, pqc, ratio) = analyze_resumption(&records);
        assert_eq!(total, 2);
        assert_eq!(pqc, 2);
        assert!((ratio - 100.0).abs() < 0.01);
    }

    #[test]
    fn dissect_psk_mode_from_payload() {
        crate::dissectors::tls::clear_tls_sessions();
        // mode=2 (resumption PSK), need 2+ bytes for the check
        let result = dissect_tls_session_resumption_pqc(None, None, 443, 54321, &[0x02, 0x00]);
        assert!(result.summary.contains("resumption PSK"));
    }

    #[test]
    fn dissect_empty_store() {
        crate::dissectors::tls::clear_tls_sessions();
        let result = dissect_tls_session_resumption_pqc(None, None, 443, 54321, &[]);
        assert_eq!(result.protocol, Protocol::TlsSessionResumptionPqc);
        assert!(result.summary.contains("0 sessions"));
    }

    #[test]
    fn dissect_with_pqc_psk() {
        crate::dissectors::tls::clear_tls_sessions();
        let r = make_record(true, true);
        crate::dissectors::tls::push_pqc_record_for_test(r);
        let result = dissect_tls_session_resumption_pqc(None, None, 443, 54321, &[0x02]);
        assert!(result.summary.contains("1 session"));
        assert!(result.summary.contains("PQC-aware PSK active"));
    }

    #[test]
    fn dissect_without_pqc_psk() {
        crate::dissectors::tls::clear_tls_sessions();
        let r = make_record(true, false);
        crate::dissectors::tls::push_pqc_record_for_test(r);
        let result = dissect_tls_session_resumption_pqc(None, None, 443, 54321, &[0x01]);
        assert!(result.summary.contains("no PQC session resumption"));
    }
}

fn analyze_resumption(records: &[crate::pqc_handshake::PqcHandshakeRecord]) -> (usize, usize, f64) {
    let total = records.len();
    if total == 0 {
        return (0, 0, 0.0);
    }

    let psk_possible = records.iter().filter(|r| r.is_0rtt).count();
    let pqc_with_psk = records.iter().filter(|r| r.used_pqc() && r.is_0rtt).count();

    let psk_ratio = if psk_possible > 0 {
        pqc_with_psk as f64 / psk_possible as f64 * 100.0
    } else {
        0.0
    };

    (psk_possible, pqc_with_psk, psk_ratio)
}

pub fn dissect_tls_session_resumption_pqc(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let records = crate::dissectors::tls::drain_pqc_store();
    let (psk_total, pqc_psk, psk_ratio) = analyze_resumption(&records);

    let psk_mode = if payload.len() > 1 {
        let mode = payload[0];
        match mode {
            0 => "no PSK",
            1 => "external PSK",
            2 => "resumption PSK",
            _ => "unknown PSK mode",
        }
    } else {
        "no PSK data"
    };

    let summary = format!(
        "TLS Session Resumption PQC: {} sessions, {} 0-RTT possible ({} PQC), ratio {:.1}%, mode: {} — {}",
        records.len(),
        psk_total,
        pqc_psk,
        psk_ratio,
        psk_mode,
        if pqc_psk > 0 {
            "PQC-aware PSK active"
        } else {
            "no PQC session resumption"
        },
    );
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TlsSessionResumptionPqc,
        summary,
    }
}
