use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

fn compute_perf_stats(
    records: &[crate::pqc_handshake::PqcHandshakeRecord],
) -> (usize, f64, f64, f64, f64, f64) {
    let total = records.len();
    if total == 0 {
        return (0, 0.0, 0.0, 0.0, 0.0, 0.0);
    }

    let pqc_count = records.iter().filter(|r| r.used_pqc()).count();
    let total_hs: f64 = records.iter().map(|r| r.total_handshake_ms as f64).sum();
    let avg_hs = total_hs / total as f64;

    let pqc_hs_times: Vec<f64> = records
        .iter()
        .filter(|r| r.used_pqc())
        .map(|r| r.total_handshake_ms as f64)
        .collect();

    let kem_times: Vec<f64> = records
        .iter()
        .filter(|r| r.used_pqc())
        .map(|r| r.pqc_kem_time_us as f64 / 1000.0)
        .collect();

    let avg_pqc = if pqc_hs_times.is_empty() {
        0.0
    } else {
        pqc_hs_times.iter().sum::<f64>() / pqc_hs_times.len() as f64
    };

    let avg_kem = if kem_times.is_empty() {
        0.0
    } else {
        kem_times.iter().sum::<f64>() / kem_times.len() as f64
    };

    let overhead = records
        .iter()
        .map(|r| r.pqc_overhead_ms as f64)
        .sum::<f64>()
        / total as f64;
    let extra_bytes: f64 = records
        .iter()
        .map(|r| r.pqc_packet_size_extra as f64)
        .sum::<f64>()
        / total as f64;

    (pqc_count, avg_hs, avg_pqc, overhead, avg_kem, extra_bytes)
}

pub fn dissect_tls_perf_benchmark_model(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    _payload: &[u8],
) -> DissectedResult {
    let records = crate::dissectors::tls::drain_pqc_store();

    let (pqc_count, avg_hs, avg_pqc_hs, overhead, avg_kem, extra_bytes) =
        compute_perf_stats(&records);

    let summary = format!(
        "TLS Perf Benchmark: {} sessions ({} PQC) — avg handshake {:.1}ms, PQC avg {:.1}ms, KEM {:.1}ms, overhead {:.1}ms, extra {:.0}B",
        records.len(),
        pqc_count,
        avg_hs,
        avg_pqc_hs,
        avg_kem,
        overhead,
        extra_bytes,
    );
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TlsPerfBenchmarkModel,
        summary,
    }
}

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
        pqc: bool,
        hs_ms: u32,
        kem_us: u64,
        overhead_ms: i32,
        extra: u16,
    ) -> PqcHandshakeRecord {
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
        r.total_handshake_ms = hs_ms;
        r.pqc_kem_time_us = kem_us;
        r.pqc_overhead_ms = overhead_ms;
        r.pqc_packet_size_extra = extra;
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
    fn compute_perf_stats_empty() {
        let result = compute_perf_stats(&[]);
        assert_eq!(result, (0, 0.0, 0.0, 0.0, 0.0, 0.0));
    }

    #[test]
    fn compute_perf_stats_one_pqc() {
        let records = vec![make_record(true, 100, 500, 10, 200)];
        let (pqc_count, avg_hs, avg_pqc_hs, overhead, avg_kem, extra_bytes) =
            compute_perf_stats(&records);
        assert_eq!(pqc_count, 1);
        assert!((avg_hs - 100.0).abs() < 0.01);
        assert!((avg_pqc_hs - 100.0).abs() < 0.01);
        assert!((overhead - 10.0).abs() < 0.01);
        assert!((avg_kem - 0.5).abs() < 0.01);
        assert!((extra_bytes - 200.0).abs() < 0.01);
    }

    #[test]
    fn compute_perf_stats_mixed() {
        let records = vec![
            make_record(true, 200, 1000, 20, 500),
            make_record(false, 50, 0, 0, 0),
        ];
        let (pqc_count, avg_hs, avg_pqc_hs, _overhead, avg_kem, _extra) =
            compute_perf_stats(&records);
        assert_eq!(pqc_count, 1);
        assert!((avg_hs - 125.0).abs() < 0.01);
        assert!((avg_pqc_hs - 200.0).abs() < 0.01);
        assert!((avg_kem - 1.0).abs() < 0.01);
    }

    #[test]
    fn dissect_empty_store() {
        crate::dissectors::tls::clear_tls_sessions();
        let result = dissect_tls_perf_benchmark_model(None, None, 443, 54321, &[]);
        assert_eq!(result.protocol, Protocol::TlsPerfBenchmarkModel);
        assert!(result.summary.contains("0 sessions"));
    }

    #[test]
    fn dissect_with_records() {
        crate::dissectors::tls::clear_tls_sessions();
        let r = make_record(true, 150, 800, 15, 300);
        crate::dissectors::tls::push_pqc_record_for_test(r);
        let result = dissect_tls_perf_benchmark_model(None, None, 443, 54321, &[]);
        assert!(result.summary.contains("1 session"));
        assert!(result.summary.contains("1 PQC"));
    }
}
