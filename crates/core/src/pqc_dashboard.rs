use crate::pqc_handshake::{KemId, PqcHandshakeStore};

/// Statistical summary for an overhead metric.
#[derive(Debug, Clone, Copy)]
pub struct OverheadStats {
    pub min: f64,
    pub max: f64,
    pub avg: f64,
    pub median: f64,
    pub p95: f64,
    pub sample_count: usize,
}

impl OverheadStats {
    fn from_values(mut values: Vec<f64>) -> Self {
        if values.is_empty() {
            return OverheadStats {
                min: 0.0, max: 0.0, avg: 0.0,
                median: 0.0, p95: 0.0, sample_count: 0,
            };
        }
        values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let n = values.len();
        let sum: f64 = values.iter().sum();
        OverheadStats {
            min: values[0],
            max: values[n - 1],
            avg: sum / n as f64,
            median: if n % 2 == 0 { (values[n / 2 - 1] + values[n / 2]) / 2.0 } else { values[n / 2] },
            p95: values[((n as f64 * 0.95).ceil() as usize).min(n - 1)],
            sample_count: n,
        }
    }
}

/// PQC Migration Dashboard — aggregates metrics from handshake records.
#[derive(Debug, Clone)]
pub struct PqcDashboard {
    store: PqcHandshakeStore,
}

impl PqcDashboard {
    pub fn new(store: PqcHandshakeStore) -> Self {
        PqcDashboard { store }
    }

    /// 1. PQC Adoption Rate — fraction of TLS handshakes using PQC.
    pub fn adoption_rate(&self) -> f64 {
        let total = self.store.total_handshakes();
        if total == 0 {
            return 0.0;
        }
        self.store.pqc_handshakes() as f64 / total as f64
    }

    /// 2. Hybrid vs Pure PQC ratio — fraction of PQC handshakes using hybrid KEM.
    pub fn hybrid_ratio(&self) -> f64 {
        let pqc_total = self.store.pqc_handshakes();
        if pqc_total == 0 {
            return 0.0;
        }
        let hybrid = self.store.records.iter().filter(|r| r.used_pqc() && r.is_hybrid_kem).count();
        hybrid as f64 / pqc_total as f64
    }

    /// 3. KEM algorithm distribution — usage counts per KemId.
    pub fn kem_distribution(&self) -> Vec<(KemId, usize)> {
        let mut counts: std::collections::HashMap<KemId, usize> = std::collections::HashMap::new();
        for rec in &self.store.records {
            for &offer in &rec.client_kem_offers {
                *counts.entry(offer).or_insert(0) += 1;
            }
            if let Some(sel) = &rec.server_kem_selected {
                *counts.entry(*sel).or_insert(0) += 1;
            }
        }
        let mut result: Vec<_> = counts.into_iter().collect();
        result.sort_by(|a, b| b.1.cmp(&a.1));
        result
    }

    /// 4. PQC latency overhead statistics (ms).
    pub fn latency_stats(&self) -> OverheadStats {
        let values: Vec<f64> = self.store.records.iter()
            .filter(|r| r.used_pqc())
            .map(|r| r.pqc_overhead_ms as f64)
            .collect();
        OverheadStats::from_values(values)
    }

    /// 5. PQC bandwidth overhead statistics (KB).
    pub fn bandwidth_stats(&self) -> OverheadStats {
        let values: Vec<f64> = self.store.records.iter()
            .filter(|r| r.used_pqc())
            .map(|r| r.pqc_packet_size_extra as f64 / 1024.0)
            .collect();
        OverheadStats::from_values(values)
    }

    /// 6. PQC handshake failure rate.
    pub fn failure_rate(&self) -> f64 {
        let total = self.store.pqc_handshakes();
        if total == 0 {
            return 0.0;
        }
        let failed = self.store.records.iter().filter(|r| r.used_pqc() && !r.is_success).count();
        failed as f64 / total as f64
    }

    /// 7. PQC certificate percentage — fraction of handshakes with PQC-signed certs.
    pub fn pqc_cert_percentage(&self) -> f64 {
        let total = self.store.total_handshakes();
        if total == 0 {
            return 0.0;
        }
        let pqc_cert = self.store.records.iter().filter(|r| r.is_pqc_signature || r.is_composite_cert).count();
        pqc_cert as f64 / total as f64
    }

    /// 8. Top-N fallback reasons.
    pub fn top_fallback_reasons(&self, n: usize) -> Vec<(String, usize)> {
        let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for rec in &self.store.records {
            if let Some(ref reason) = rec.pqc_fallback_reason {
                *counts.entry(reason.clone()).or_insert(0) += 1;
            }
        }
        let mut result: Vec<_> = counts.into_iter().collect();
        result.sort_by(|a, b| b.1.cmp(&a.1));
        result.truncate(n);
        result
    }

    /// Generate a formatted dashboard report string.
    pub fn generate_report(&self) -> String {
        let adoption = self.adoption_rate() * 100.0;
        let hybrid = self.hybrid_ratio() * 100.0;
        let latency = self.latency_stats();
        let bw = self.bandwidth_stats();
        let fail = self.failure_rate() * 100.0;
        let cert_pct = self.pqc_cert_percentage() * 100.0;
        let kem_dist = self.kem_distribution();
        let fallbacks = self.top_fallback_reasons(5);

        let target_latency = if latency.avg < 50.0 { "✓" } else { "✗" };
        let target_bw = if bw.avg < 10.0 { "✓" } else { "✗" };
        let target_fail = if fail < 1.0 { "✓" } else { "✗" };
        let target_hybrid = if hybrid > 90.0 { "✓" } else { "✗" };

        let mut report = String::new();
        report.push_str("═══ PQC Migration Dashboard ═══\n\n");

        report.push_str(&format!("1. PQC Adoption Rate:      {adoption:>6.1}%  (trend: ↑)\n"));
        report.push_str(&format!("2. Hybrid vs Pure PQC:    {hybrid:>6.1}%  (target > 90%) {target_hybrid}\n"));
        report.push_str(&format!("3. Failure Rate:           {fail:>6.1}%  (target < 1%)  {target_fail}\n"));
        report.push_str(&format!("4. PQC Certificate %:      {cert_pct:>6.1}%  (trend: ↑)\n\n"));

        report.push_str("── Latency Overhead (ms) ──\n");
        report.push_str(&format!("   avg={:.1}  p95={:.1}  max={:.1}  samples={}  (target < 50ms) {target_latency}\n",
            latency.avg, latency.p95, latency.max, latency.sample_count));

        report.push_str("── Bandwidth Overhead (KB) ──\n");
        report.push_str(&format!("   avg={:.1}  p95={:.1}  max={:.1}  samples={}  (target < 10KB) {target_bw}\n",
            bw.avg, bw.p95, bw.max, bw.sample_count));

        report.push_str("\n── KEM Algorithm Distribution ──\n");
        let total_kem: usize = kem_dist.iter().map(|(_, c)| c).sum();
        for (alg, count) in &kem_dist {
            let pct = *count as f64 / total_kem.max(1) as f64 * 100.0;
            report.push_str(&format!("   {alg:25} {count:>4} ({pct:>5.1}%)\n"));
        }

        report.push_str("\n── Top-5 Fallback Reasons ──\n");
        if fallbacks.is_empty() {
            report.push_str("   (none)\n");
        } else {
            for (reason, count) in &fallbacks {
                report.push_str(&format!("   {count:>4} × {reason}\n"));
            }
        }
        report.push_str("\n══════════════════════════════\n");
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pair_correlation::FiveTuple;
    use crate::pqc_handshake::{PqcHandshakeRecord, SigAlgorithm, TlsVersion, Timestamp, PqcKem, KemId};
    use chrono::Utc;
    use std::net::IpAddr;

    fn test_ft() -> FiveTuple {
        FiveTuple {
            src_ip: "10.0.0.1".parse::<IpAddr>().unwrap(),
            src_port: 54321,
            dst_ip: "93.184.216.34".parse::<IpAddr>().unwrap(),
            dst_port: 443,
            protocol: 6,
        }
    }

    fn make_pqc_record(overhead_ms: i32, extra_bytes: u16, hybrid: bool, success: bool, fallback: Option<&str>) -> PqcHandshakeRecord {
        let mut rec = PqcHandshakeRecord::new(
            test_ft(), TlsVersion::TlsV1_3, "pqc.example".into(),
            SigAlgorithm::MlDsa65, Utc::now(),
        );
        rec.is_hybrid_kem = hybrid;
        rec.pqc_overhead_ms = overhead_ms;
        rec.pqc_packet_size_extra = extra_bytes;
        rec.is_success = success;
        rec.pqc_fallback_reason = fallback.map(String::from);
        rec
    }

    fn make_classic_record() -> PqcHandshakeRecord {
        PqcHandshakeRecord::new(
            test_ft(), TlsVersion::TlsV1_2, "classic.example".into(),
            SigAlgorithm::RsaPkcs1Sha256, Utc::now(),
        )
    }

    #[test]
    fn empty_dashboard() {
        let store = PqcHandshakeStore::new();
        let dash = PqcDashboard::new(store);
        assert_eq!(dash.adoption_rate(), 0.0);
        assert_eq!(dash.hybrid_ratio(), 0.0);
        assert_eq!(dash.failure_rate(), 0.0);
        assert_eq!(dash.pqc_cert_percentage(), 0.0);
        assert!(dash.top_fallback_reasons(5).is_empty());
    }

    #[test]
    fn adoption_rate_mixed() {
        let mut store = PqcHandshakeStore::new();
        store.push(make_pqc_record(10, 500, true, true, None));
        store.push(make_pqc_record(20, 1000, false, true, None));
        store.push(make_classic_record());
        let dash = PqcDashboard::new(store);
        assert!((dash.adoption_rate() - 2.0 / 3.0).abs() < 1e-10);
    }

    #[test]
    fn hybrid_ratio() {
        let mut store = PqcHandshakeStore::new();
        store.push(make_pqc_record(10, 500, true, true, None));
        store.push(make_pqc_record(20, 1000, false, true, None));
        store.push(make_pqc_record(30, 1500, true, true, None));
        let dash = PqcDashboard::new(store);
        assert!((dash.hybrid_ratio() - 2.0 / 3.0).abs() < 1e-10);
    }

    #[test]
    fn kem_distribution_includes_client_offers_and_server_selected() {
        let mut store = PqcHandshakeStore::new();
        let mut rec = make_pqc_record(5, 200, true, true, None);
        rec.client_kem_offers = vec![KemId::MlKem768, KemId::MlKem1024, KemId::BikeL5];
        rec.server_kem_selected = Some(KemId::MlKem768);
        store.push(rec);

        let dash = PqcDashboard::new(store);
        let dist = dash.kem_distribution();
        assert!(!dist.is_empty());
        let total: usize = dist.iter().map(|(_, c)| c).sum();
        assert_eq!(total, 4); // 3 offers + 1 selected
    }

    #[test]
    fn latency_stats_with_data() {
        let mut store = PqcHandshakeStore::new();
        store.push(make_pqc_record(10, 500, true, true, None));
        store.push(make_pqc_record(20, 1000, true, true, None));
        store.push(make_pqc_record(30, 1500, true, true, None));
        let dash = PqcDashboard::new(store);
        let ls = dash.latency_stats();
        assert_eq!(ls.sample_count, 3);
        assert!((ls.avg - 20.0).abs() < 1e-10);
        assert!((ls.min - 10.0).abs() < 1e-10);
        assert!((ls.max - 30.0).abs() < 1e-10);
    }

    #[test]
    fn bandwidth_stats_kb() {
        let mut store = PqcHandshakeStore::new();
        store.push(make_pqc_record(10, 2048, true, true, None));
        let dash = PqcDashboard::new(store);
        let bs = dash.bandwidth_stats();
        assert!((bs.avg - 2.0).abs() < 1e-10);
    }

    #[test]
    fn failure_rate() {
        let mut store = PqcHandshakeStore::new();
        store.push(make_pqc_record(10, 500, true, true, None));
        store.push(make_pqc_record(20, 1000, true, false, Some("timeout")));
        store.push(make_pqc_record(30, 1500, true, false, Some("no_matching_kem")));
        let dash = PqcDashboard::new(store);
        assert!((dash.failure_rate() - 2.0 / 3.0).abs() < 1e-10);
    }

    #[test]
    fn pqc_cert_percentage() {
        let mut store = PqcHandshakeStore::new();
        store.push(make_pqc_record(10, 500, true, true, None));
        store.push(make_classic_record());
        store.push(make_classic_record());
        let dash = PqcDashboard::new(store);
        assert!((dash.pqc_cert_percentage() - 1.0 / 3.0).abs() < 1e-10);
    }

    #[test]
    fn top_fallback_reasons() {
        let mut store = PqcHandshakeStore::new();
        store.push(make_pqc_record(10, 500, true, false, Some("timeout")));
        store.push(make_pqc_record(20, 1000, true, false, Some("timeout")));
        store.push(make_pqc_record(30, 1500, true, false, Some("no_matching_kem")));
        let dash = PqcDashboard::new(store);
        let top = dash.top_fallback_reasons(5);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].0, "timeout");
        assert_eq!(top[0].1, 2);
    }

    #[test]
    fn generate_report_includes_all_sections() {
        let mut store = PqcHandshakeStore::new();
        store.push(make_pqc_record(10, 500, true, true, None));
        store.push(make_classic_record());
        let dash = PqcDashboard::new(store);
        let report = dash.generate_report();
        assert!(report.contains("PQC Migration Dashboard"));
        assert!(report.contains("Adoption Rate"));
        assert!(report.contains("Hybrid vs Pure"));
        assert!(report.contains("Failure Rate"));
        assert!(report.contains("Certificate"));
        assert!(report.contains("Latency Overhead"));
        assert!(report.contains("Bandwidth Overhead"));
        assert!(report.contains("KEM Algorithm Distribution"));
        assert!(report.contains("Fallback Reasons"));
    }

    #[test]
    fn overhead_stats_empty() {
        let stats = OverheadStats::from_values(vec![]);
        assert_eq!(stats.sample_count, 0);
    }

    #[test]
    fn overhead_stats_single_value() {
        let stats = OverheadStats::from_values(vec![42.0]);
        assert!((stats.avg - 42.0).abs() < 1e-10);
        assert!((stats.min - 42.0).abs() < 1e-10);
        assert!((stats.max - 42.0).abs() < 1e-10);
    }
}
