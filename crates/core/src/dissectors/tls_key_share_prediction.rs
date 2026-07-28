use std::net::IpAddr;

use crate::models::Protocol;
use crate::pqc_handshake::PqcHandshakeStore;

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
        fallback: Option<&str>,
    ) -> PqcHandshakeRecord {
        let mut r = PqcHandshakeRecord::new(
            test_ft(),
            TlsVersion::TlsV1_3,
            "example.com".into(),
            SigAlgorithm::MlDsa65,
            Utc::now(),
        );
        r.is_success = success;
        r.pqc_fallback_reason = fallback.map(String::from);
        if let Some(k) = kem {
            r.pqc_kem = Some(PqcKem {
                algorithm: k,
                public_key: None,
                ciphertext: None,
                shared_secret: None,
            });
            r.server_kem_selected = Some(k);
        }
        r
    }

    #[test]
    fn predict_failure_rate_empty() {
        let store = PqcHandshakeStore::new();
        let (failures, rate) = predict_failure_rate(&store);
        assert_eq!(failures, 0);
        assert_eq!(rate, 0.0);
    }

    #[test]
    fn predict_failure_rate_all_success() {
        let mut store = PqcHandshakeStore::new();
        store.push(make_record(true, Some(KemId::MlKem768), None));
        store.push(make_record(true, Some(KemId::MlKem512), None));
        let (failures, rate) = predict_failure_rate(&store);
        assert_eq!(failures, 0);
        assert_eq!(rate, 0.0);
    }

    #[test]
    fn predict_failure_rate_mixed() {
        let mut store = PqcHandshakeStore::new();
        store.push(make_record(true, Some(KemId::MlKem768), None));
        store.push(make_record(false, Some(KemId::MlKem512), Some("timeout")));
        let (failures, rate) = predict_failure_rate(&store);
        assert_eq!(failures, 1);
        assert!((rate - 50.0).abs() < 0.01);
    }

    #[test]
    fn find_mismatches_none() {
        let mut store = PqcHandshakeStore::new();
        store.push(make_record(true, Some(KemId::MlKem768), None));
        let result = find_mismatches(&store);
        assert!(result.is_empty());
    }

    #[test]
    fn find_mismatches_with_failures() {
        let mut store = PqcHandshakeStore::new();
        store.push(make_record(false, Some(KemId::MlKem768), Some("timeout")));
        store.push(make_record(true, Some(KemId::MlKem512), None));
        let result = find_mismatches(&store);
        assert_eq!(result.len(), 1);
        assert!(result[0].contains("MlKem768"));
    }

    #[test]
    fn dissect_empty_store() {
        crate::dissectors::tls::clear_tls_sessions();
        let result = dissect_tls_key_share_prediction(None, None, 443, 54321, &[]);
        assert_eq!(result.protocol, Protocol::TlsKeySharePrediction);
        assert!(result.summary.contains("0 sessions"));
    }

    #[test]
    fn dissect_with_records() {
        crate::dissectors::tls::clear_tls_sessions();
        let ft = test_ft();
        let r = PqcHandshakeRecord::new(
            ft,
            TlsVersion::TlsV1_3,
            "example.com".into(),
            SigAlgorithm::RsaPkcs1Sha256,
            Utc::now(),
        );
        crate::dissectors::tls::push_pqc_record_for_test(r);
        let result = dissect_tls_key_share_prediction(None, None, 443, 54321, &[]);
        assert!(result.summary.contains("1 session"));
    }
}

fn predict_failure_rate(store: &PqcHandshakeStore) -> (usize, f64) {
    let records = &store.records;
    if records.is_empty() {
        return (0, 0.0);
    }
    let failures = records.iter().filter(|r| !r.is_success).count();
    let rate = failures as f64 / records.len() as f64 * 100.0;
    (failures, rate)
}

fn find_mismatches(store: &PqcHandshakeStore) -> Vec<String> {
    store
        .records
        .iter()
        .filter_map(|r| {
            if r.pqc_kem.is_some() && !r.is_success {
                let kem = r
                    .pqc_kem
                    .as_ref()
                    .map(|k| format!("{:?}", k.algorithm))
                    .unwrap_or_else(|| "unknown".into());
                Some(format!(
                    "KEM {} failed (fallback: {:?})",
                    kem, r.pqc_fallback_reason
                ))
            } else {
                None
            }
        })
        .collect()
}

pub fn dissect_tls_key_share_prediction(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    _payload: &[u8],
) -> DissectedResult {
    let records = crate::dissectors::tls::drain_pqc_store();
    let mut store = PqcHandshakeStore::new();
    for r in records {
        store.push(r);
    }

    let (failures, fail_rate) = predict_failure_rate(&store);
    let mismatches = find_mismatches(&store);
    let total = store.total_handshakes();

    let predictions = if mismatches.is_empty() {
        "no failures predicted".into()
    } else {
        format!(
            "{} predicted failures: {}",
            mismatches.len(),
            mismatches.join("; ")
        )
    };

    let summary = format!(
        "Key Share Prediction: {} sessions, {} failures ({:.1}%), {} — {}",
        total,
        failures,
        fail_rate,
        predictions,
        if fail_rate > 20.0 {
            "HIGH RISK: KEM negotiation may fail"
        } else if fail_rate > 5.0 {
            "MEDIUM: elevated failure rate"
        } else {
            "LOW: stable key share negotiation"
        },
    );
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TlsKeySharePrediction,
        summary,
    }
}
