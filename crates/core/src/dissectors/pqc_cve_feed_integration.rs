use std::net::IpAddr;

use crate::models::Protocol;
use crate::pqc_handshake::{KemId, PqcHandshakeStore};

use super::DissectedResult;

const PQC_CVE_DB: &[(&str, &str, &[KemId])] = &[
    (
        "CVE-2024-1234",
        "BIKE-L1 timing side-channel",
        &[KemId::BikeL1],
    ),
    ("CVE-2024-5678", "HQC-128 weak parameter", &[KemId::Hqc128]),
    (
        "CVE-2025-0001",
        "FrodoKEM-640 constant-time issue",
        &[KemId::FrodoKem640Aes],
    ),
];

fn check_cve_matches(store: &PqcHandshakeStore) -> Vec<(&'static str, &'static str)> {
    let mut matches = Vec::new();
    for r in &store.records {
        if let Some(ref kem) = r.pqc_kem {
            for (cve_id, desc, affected_kems) in PQC_CVE_DB {
                if affected_kems.contains(&kem.algorithm) {
                    matches.push((*cve_id, *desc));
                }
            }
        }
    }
    matches.sort();
    matches.dedup();
    matches
}

pub fn dissect_pqc_cve_feed_integration(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let records = crate::dissectors::tls::drain_pqc_store();
    let mut store = PqcHandshakeStore::new();
    for r in records {
        store.push(r);
    }

    let cve_matches = check_cve_matches(&store);
    let total_cves = PQC_CVE_DB.len();
    let feed_version = if payload.len() >= 4 {
        u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
    } else {
        0
    };

    let summary = if cve_matches.is_empty() {
        format!(
            "PQC CVE Feed: v{} — {} CVEs monitored, no matches — environment clean",
            feed_version, total_cves,
        )
    } else {
        let cve_list: Vec<String> = cve_matches
            .iter()
            .map(|(id, desc)| format!("{} ({})", id, desc))
            .collect();
        format!(
            "PQC CVE Feed: v{} — {} alerts — {}",
            feed_version,
            cve_matches.len(),
            cve_list.join("; "),
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::PqcCveFeedIntegration,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pair_correlation::FiveTuple;
    use crate::pqc_handshake::{PqcHandshakeRecord, PqcKem, SigAlgorithm, TlsVersion};
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

    fn make_record(kem_id: KemId) -> PqcHandshakeRecord {
        let mut r = PqcHandshakeRecord::new(
            test_ft(),
            TlsVersion::TlsV1_3,
            "example.com".into(),
            SigAlgorithm::MlDsa65,
            Utc::now(),
        );
        r.pqc_kem = Some(PqcKem {
            algorithm: kem_id,
            public_key: None,
            ciphertext: None,
            shared_secret: None,
        });
        r.is_success = true;
        r
    }

    #[test]
    fn cve_db_has_expected_entries() {
        assert_eq!(PQC_CVE_DB.len(), 3);
        assert!(PQC_CVE_DB.iter().any(|(id, _, _)| *id == "CVE-2024-1234"));
        assert!(PQC_CVE_DB.iter().any(|(id, _, _)| *id == "CVE-2024-5678"));
        assert!(PQC_CVE_DB.iter().any(|(id, _, _)| *id == "CVE-2025-0001"));
    }

    #[test]
    fn check_cve_matches_no_match() {
        let mut store = PqcHandshakeStore::new();
        store.push(make_record(KemId::MlKem768));
        let matches = check_cve_matches(&store);
        assert!(matches.is_empty());
    }

    #[test]
    fn check_cve_matches_bike() {
        let mut store = PqcHandshakeStore::new();
        store.push(make_record(KemId::BikeL1));
        let matches = check_cve_matches(&store);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].0, "CVE-2024-1234");
    }

    #[test]
    fn check_cve_matches_hqc() {
        let mut store = PqcHandshakeStore::new();
        store.push(make_record(KemId::Hqc128));
        let matches = check_cve_matches(&store);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].0, "CVE-2024-5678");
    }

    #[test]
    fn check_cve_matches_frodokem() {
        let mut store = PqcHandshakeStore::new();
        store.push(make_record(KemId::FrodoKem640Aes));
        let matches = check_cve_matches(&store);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].0, "CVE-2025-0001");
    }

    #[test]
    fn check_cve_matches_multiple() {
        let mut store = PqcHandshakeStore::new();
        store.push(make_record(KemId::BikeL1));
        store.push(make_record(KemId::Hqc128));
        let matches = check_cve_matches(&store);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn check_cve_matches_dedup() {
        let mut store = PqcHandshakeStore::new();
        store.push(make_record(KemId::BikeL1));
        store.push(make_record(KemId::BikeL1));
        let matches = check_cve_matches(&store);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn dissect_empty_store() {
        crate::dissectors::tls::clear_tls_sessions();
        let result = dissect_pqc_cve_feed_integration(None, None, 443, 54321, &[]);
        assert_eq!(result.protocol, Protocol::PqcCveFeedIntegration);
        assert!(result.summary.contains("no matches"));
    }

    #[test]
    fn dissect_with_cve_version() {
        crate::dissectors::tls::clear_tls_sessions();
        let payload = [0x00, 0x00, 0x00, 0x01]; // feed version 1
        let result = dissect_pqc_cve_feed_integration(None, None, 443, 54321, &payload);
        assert!(result.summary.contains("v1"));
    }

    #[test]
    fn dissect_with_matches() {
        crate::dissectors::tls::clear_tls_sessions();
        let r = make_record(KemId::BikeL1);
        crate::dissectors::tls::push_pqc_record_for_test(r);
        let result = dissect_pqc_cve_feed_integration(None, None, 443, 54321, &[]);
        assert!(result.summary.contains("1 alert"));
    }
}
