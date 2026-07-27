use std::collections::HashMap;

use crate::pqc_handshake::{KemId, PqcHandshakeRecord, PqcHandshakeStore, SigAlgorithm};

#[derive(Debug, Clone)]
pub struct TlsPqcWizardReport {
    pub overview: WizardOverview,
    pub algorithms: Vec<KemDetail>,
    pub vulnerabilities: Vec<VulnerabilityFinding>,
    pub recommendations: Vec<Recommendation>,
    pub raw_records: usize,
}

#[derive(Debug, Clone)]
pub struct WizardOverview {
    pub total_handshakes: usize,
    pub pqc_handshakes: usize,
    pub hybrid_handshakes: usize,
    pub pure_pqc_handshakes: usize,
    pub failed_handshakes: usize,
    pub adoption_rate: f64,
    pub hybrid_ratio: f64,
    pub avg_latency_us: f64,
    pub avg_bandwidth_extra_bytes: f64,
    pub pqc_signature_ratio: f64,
    pub composite_cert_ratio: f64,
    pub risk_score: RiskScore,
}

#[derive(Debug, Clone)]
pub struct KemDetail {
    pub algorithm: KemId,
    pub count: usize,
    pub is_hybrid_used: bool,
    pub avg_latency_us: f64,
    pub avg_bandwidth_extra: u16,
    pub failure_count: usize,
    pub security_level: SecurityLevelTag,
}

#[derive(Debug, Clone)]
pub struct VulnerabilityFinding {
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub affected_count: usize,
    pub cve_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskScore {
    Safe,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct Recommendation {
    pub priority: Priority,
    pub action: String,
    pub rationale: String,
    pub affected_endpoints: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Priority {
    Immediate,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityLevelTag {
    Level1,
    Level3,
    Level5,
    Unknown,
}

pub struct Tls13PqcWizard;

impl Tls13PqcWizard {
    pub fn analyze(store: &PqcHandshakeStore) -> TlsPqcWizardReport {
        let records = &store.records;
        let total = records.len();
        let pqc: Vec<_> = records.iter().filter(|r| r.used_pqc()).collect();
        let successful: Vec<_> = pqc.iter().filter(|r| r.is_success).copied().collect();
        let failed: Vec<_> = pqc.iter().filter(|r| !r.is_success).copied().collect();
        let hybrid: Vec<_> = pqc.iter().filter(|r| r.is_hybrid_kem).copied().collect();
        let pure_pqc: Vec<_> = pqc.iter().filter(|r| !r.is_hybrid_kem).copied().collect();

        let avg_latency = if !successful.is_empty() {
            successful.iter().map(|r| r.pqc_kem_time_us as f64).sum::<f64>() / successful.len() as f64
        } else {
            0.0
        };

        let avg_bandwidth = if !successful.is_empty() {
            successful.iter().map(|r| r.pqc_packet_size_extra as f64).sum::<f64>() / successful.len() as f64
        } else {
            0.0
        };

        let pqc_sig_count = pqc.iter().filter(|r| r.is_pqc_signature).count();
        let composite_cert_count = pqc.iter().filter(|r| r.is_composite_cert).count();

        let adoption_rate = if total > 0 { pqc.len() as f64 / total as f64 * 100.0 } else { 0.0 };
        let hybrid_ratio = if !pqc.is_empty() { hybrid.len() as f64 / pqc.len() as f64 * 100.0 } else { 0.0 };
        let pqc_sig_ratio = if !pqc.is_empty() { pqc_sig_count as f64 / pqc.len() as f64 * 100.0 } else { 0.0 };
        let composite_cert_ratio = if !pqc.is_empty() { composite_cert_count as f64 / pqc.len() as f64 * 100.0 } else { 0.0 };

        let risk_score = evaluate_risk(adoption_rate, &failed, &successful);

        let overview = WizardOverview {
            total_handshakes: total,
            pqc_handshakes: pqc.len(),
            hybrid_handshakes: hybrid.len(),
            pure_pqc_handshakes: pure_pqc.len(),
            failed_handshakes: failed.len(),
            adoption_rate,
            hybrid_ratio,
            avg_latency_us: avg_latency,
            avg_bandwidth_extra_bytes: avg_bandwidth,
            pqc_signature_ratio: pqc_sig_ratio,
            composite_cert_ratio,
            risk_score,
        };
        let algorithms = build_kem_details(&pqc);
        let vulnerabilities = find_vulnerabilities(&pqc, &failed, total);
        let recommendations = build_recommendations(&overview, &vulnerabilities, &algorithms);

        TlsPqcWizardReport {
            overview,
            algorithms,
            vulnerabilities,
            recommendations,
            raw_records: records.len(),
        }
    }
}

fn evaluate_risk(adoption_rate: f64, failed: &[&PqcHandshakeRecord], _successful: &[&PqcHandshakeRecord]) -> RiskScore {
    if adoption_rate == 0.0 {
        return RiskScore::Critical;
    }
    if adoption_rate < 10.0 {
        return RiskScore::High;
    }
    if !failed.is_empty() {
        let fail_ratio = failed.len() as f64 / (failed.len() + _successful.len()).max(1) as f64 * 100.0;
        if fail_ratio > 20.0 {
            return RiskScore::High;
        }
        if fail_ratio > 5.0 {
            return RiskScore::Medium;
        }
    }
    if adoption_rate > 80.0 {
        RiskScore::Safe
    } else if adoption_rate > 50.0 {
        RiskScore::Low
    } else {
        RiskScore::Medium
    }
}

fn build_kem_details(pqc_records: &[&PqcHandshakeRecord]) -> Vec<KemDetail> {
    let mut kem_groups: HashMap<KemId, Vec<&PqcHandshakeRecord>> = HashMap::new();
    for rec in pqc_records {
        if let Some(kem) = &rec.server_kem_selected {
            kem_groups.entry(*kem).or_default().push(rec);
        }
    }
    let mut details: Vec<KemDetail> = kem_groups
        .into_iter()
        .map(|(kem, group)| {
            let count = group.len();
            let failures = group.iter().filter(|r| !r.is_success).count();
            let successful: Vec<&&PqcHandshakeRecord> = group.iter().filter(|r| r.is_success).collect();
            let avg_lat = if !successful.is_empty() {
                successful.iter().map(|r| r.pqc_kem_time_us as f64).sum::<f64>() / successful.len() as f64
            } else {
                0.0
            };
            let avg_bw = if !successful.is_empty() {
                successful.iter().map(|r| r.pqc_packet_size_extra as f64).sum::<f64>() / successful.len() as f64
            } else {
                0.0
            };
            let hybrid_used = group.iter().any(|r| r.is_hybrid_kem);
            let sl = kem_security_level(&kem);
            KemDetail {
                algorithm: kem,
                count,
                is_hybrid_used: hybrid_used,
                avg_latency_us: avg_lat,
                avg_bandwidth_extra: avg_bw as u16,
                failure_count: failures,
                security_level: sl,
            }
        })
        .collect();
    details.sort_by(|a, b| b.count.cmp(&a.count));
    details
}

fn kem_security_level(kem: &KemId) -> SecurityLevelTag {
    match kem {
        KemId::MlKem512 | KemId::MlKem768 | KemId::FrodoKem640Aes | KemId::BikeL1 | KemId::Hqc128 | KemId::Sntrup761 => SecurityLevelTag::Level1,
        KemId::MlKem1024 | KemId::FrodoKem976Aes | KemId::FrodoKem1344Aes | KemId::ClassicMcEliece460896 | KemId::BikeL3 | KemId::Hqc192 => SecurityLevelTag::Level3,
        KemId::ClassicMcEliece348864 | KemId::ClassicMcEliece6688128 | KemId::BikeL5 | KemId::Hqc256 => SecurityLevelTag::Level5,
        _ => SecurityLevelTag::Unknown,
    }
}

fn find_vulnerabilities(
    pqc_records: &[&PqcHandshakeRecord],
    failed: &[&PqcHandshakeRecord],
    total: usize,
) -> Vec<VulnerabilityFinding> {
    let mut vulns = Vec::new();

    if failed.len() * 10 >= total {
        vulns.push(VulnerabilityFinding {
            severity: Severity::High,
            title: "High PQC handshake failure rate".into(),
            description: format!("{} of {} PQC handshakes failed — possible downgrade or compatibility issue", failed.len(), pqc_records.len()),
            affected_count: failed.len(),
            cve_ref: None,
        });
    }

    let no_pqc: Vec<&&PqcHandshakeRecord> = pqc_records.iter().filter(|r| !r.used_pqc()).collect();
    if !no_pqc.is_empty() {
        vulns.push(VulnerabilityFinding {
            severity: Severity::Medium,
            title: "Classic-only handshakes detected".into(),
            description: format!("{} handshakes used only classical crypto — no PQC negotiation", no_pqc.len()),
            affected_count: no_pqc.len(),
            cve_ref: None,
        });
    }

    let fallback = pqc_records.iter().filter(|r| r.pqc_fallback_reason.is_some());
    for rec in fallback {
        if let Some(reason) = &rec.pqc_fallback_reason {
            vulns.push(VulnerabilityFinding {
                severity: Severity::High,
                title: "PQC fallback triggered".into(),
                description: format!("Fallback reason: {}", reason),
                affected_count: 1,
                cve_ref: None,
            });
        }
    }

    let weak_sig = pqc_records.iter().filter(|r| !r.is_pqc_signature && r.cert_sig_algorithm != SigAlgorithm::Unknown(0));
    let weak_count = weak_sig.count();
    if weak_count > 0 {
        vulns.push(VulnerabilityFinding {
            severity: Severity::Medium,
            title: "Non-PQC signatures in PQC handshake".into(),
            description: format!("{} handshake(s) use classical signatures — certificate chain is not quantum-safe", weak_count),
            affected_count: weak_count,
            cve_ref: None,
        });
    }

    if !pqc_records.is_empty() {
        let has_l1 = pqc_records.iter().any(|r| r.server_kem_selected.is_some_and(|k| matches!(k, KemId::MlKem512 | KemId::FrodoKem640Aes | KemId::BikeL1 | KemId::Hqc128)));
        if has_l1 {
            vulns.push(VulnerabilityFinding {
                severity: Severity::Low,
                title: "NIST Level 1 KEM in use".into(),
                description: "Minimum security level — consider Level 3 or Level 5 for long-term protection".into(),
                affected_count: pqc_records.len(),
                cve_ref: None,
            });
        }
    }

    vulns
}

fn build_recommendations(
    overview: &WizardOverview,
    vulnerabilities: &[VulnerabilityFinding],
    _algorithms: &[KemDetail],
) -> Vec<Recommendation> {
    let mut recs = Vec::new();

    if overview.adoption_rate < 50.0 {
        recs.push(Recommendation {
            priority: Priority::High,
            action: "Enable PQC on all TLS 1.3 endpoints".into(),
            rationale: format!("Only {:.1}% of handshakes use PQC — migrate remaining endpoints to avoid quantum risk", overview.adoption_rate),
            affected_endpoints: overview.total_handshakes - overview.pqc_handshakes,
        });
    }

    if overview.hybrid_ratio > 50.0 {
        recs.push(Recommendation {
            priority: Priority::Medium,
            action: "Evaluate pure PQC migration".into(),
            rationale: format!("{:.1}% of PQC handshakes are hybrid — pure PQC reduces complexity and attack surface", overview.hybrid_ratio),
            affected_endpoints: overview.hybrid_handshakes,
        });
    }

    if overview.composite_cert_ratio < 50.0 && overview.pqc_handshakes > 0 {
        recs.push(Recommendation {
            priority: Priority::Medium,
            action: "Adopt composite certificates (RSA + Dilithium)".into(),
            rationale: "Only a fraction of PQC handshakes use composite certs — migrate CA to issue hybrid certificates".into(),
            affected_endpoints: overview.pqc_handshakes,
        });
    }

    if overview.avg_latency_us > 10_000.0 {
        recs.push(Recommendation {
            priority: Priority::Low,
            action: "Optimize KEM selection for latency".into(),
            rationale: format!("Average PQC latency {:.0} µs — consider ML-KEM (Kyber) for lower overhead", overview.avg_latency_us),
            affected_endpoints: overview.pqc_handshakes,
        });
    }

    let has_fallback_vuln = vulnerabilities.iter().any(|v| v.title.contains("fallback"));
    if has_fallback_vuln {
        recs.push(Recommendation {
            priority: Priority::Immediate,
            action: "Investigate PQC fallback triggers".into(),
            rationale: "PQC handshakes are falling back to classical — check server configuration and client support".into(),
            affected_endpoints: 1,
        });
    }

    recs
}

impl TlsPqcWizardReport {
    pub fn is_empty(&self) -> bool {
        self.raw_records == 0
    }
}

impl RiskScore {
    pub fn label(&self) -> &'static str {
        match self {
            RiskScore::Safe => "SAFE",
            RiskScore::Low => "LOW",
            RiskScore::Medium => "MEDIUM",
            RiskScore::High => "HIGH",
            RiskScore::Critical => "CRITICAL",
        }
    }
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

impl Priority {
    pub fn label(&self) -> &'static str {
        match self {
            Priority::Immediate => "IMMEDIATE",
            Priority::High => "HIGH",
            Priority::Medium => "MEDIUM",
            Priority::Low => "LOW",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pqc_handshake::{PqcKem, TlsVersion};
    use chrono::Utc;

    fn make_record(kem: Option<KemId>, hybrid: bool, success: bool, sig: SigAlgorithm) -> PqcHandshakeRecord {
        PqcHandshakeRecord {
            connection_5tuple: crate::pair_correlation::FiveTuple {
                src_ip: "10.0.0.1".parse().unwrap(),
                src_port: 443,
                dst_ip: "10.0.0.2".parse().unwrap(),
                dst_port: 12345,
                protocol: 6,
            },
            tls_version: TlsVersion::TlsV1_3,
            server_name: "example.com".into(),
            client_kem_offers: kem.map(|k| vec![k, KemId::MlKem768]).unwrap_or_default(),
            server_kem_selected: kem,
            is_hybrid_kem: hybrid,
            classical_group: None,
            pqc_kem: Some(PqcKem {
                algorithm: kem.unwrap_or(KemId::MlKem768),
                public_key: None,
                ciphertext: None,
                shared_secret: None,
            }),
            shared_secret_size: 32,
            cert_sig_algorithm: sig,
            is_pqc_signature: sig.is_pqc(),
            is_composite_cert: false,
            cert_chain_pqc_count: 0,
            pqc_kem_time_us: 5000,
            pqc_sig_verify_us: 2000,
            total_handshake_ms: 50,
            pqc_overhead_ms: 10,
            pqc_packet_size_extra: 1200,
            timestamp: Utc::now(),
            is_success: success,
            pqc_fallback_reason: if success { None } else { Some("Unsupported KEM".into()) },
        }
    }

    #[test]
    fn empty_store_report() {
        let store = PqcHandshakeStore::new();
        let report = Tls13PqcWizard::analyze(&store);
        assert!(report.is_empty());
        assert_eq!(report.overview.risk_score, RiskScore::Critical);
    }

    #[test]
    fn full_pqc_handshake_analyzed() {
        let mut store = PqcHandshakeStore::new();
        store.push(make_record(Some(KemId::MlKem768), false, true, SigAlgorithm::MlDsa65));
        let report = Tls13PqcWizard::analyze(&store);
        assert_eq!(report.overview.pqc_handshakes, 1);
        assert_eq!(report.overview.adoption_rate, 100.0);
        assert_eq!(report.overview.risk_score, RiskScore::Safe);
        assert_eq!(report.algorithms.len(), 1);
        assert_eq!(report.algorithms[0].algorithm, KemId::MlKem768);
    }

    #[test]
    fn hybrid_handshake_detected() {
        let mut store = PqcHandshakeStore::new();
        store.push(make_record(Some(KemId::MlKem768), true, true, SigAlgorithm::MlDsa65));
        let report = Tls13PqcWizard::analyze(&store);
        assert_eq!(report.overview.hybrid_handshakes, 1);
        assert!(report.overview.hybrid_ratio > 0.0);
    }

    #[test]
    fn failed_handshake_triggers_vulnerability() {
        let mut store = PqcHandshakeStore::new();
        for _ in 0..9 {
            store.push(make_record(Some(KemId::MlKem768), false, true, SigAlgorithm::MlDsa65));
        }
        store.push(make_record(Some(KemId::MlKem768), false, false, SigAlgorithm::MlDsa65));
        let report = Tls13PqcWizard::analyze(&store);
        assert!(report.overview.failed_handshakes > 0);
        let has_fail_vuln = report.vulnerabilities.iter().any(|v| v.title.contains("failure"));
        assert!(has_fail_vuln);
    }

    #[test]
    fn classic_only_handshake_detected() {
        let mut store = PqcHandshakeStore::new();
        store.push(PqcHandshakeRecord {
            connection_5tuple: crate::pair_correlation::FiveTuple {
                src_ip: "10.0.0.1".parse().unwrap(),
                src_port: 443, dst_ip: "10.0.0.2".parse().unwrap(),
                dst_port: 12345, protocol: 6,
            },
            tls_version: TlsVersion::TlsV1_3,
            server_name: "example.com".into(),
            client_kem_offers: vec![],
            server_kem_selected: None,
            is_hybrid_kem: false,
            classical_group: None,
            pqc_kem: None,
            shared_secret_size: 32,
            cert_sig_algorithm: SigAlgorithm::RsaPkcs1Sha256,
            is_pqc_signature: false,
            is_composite_cert: false,
            cert_chain_pqc_count: 0,
            pqc_kem_time_us: 0,
            pqc_sig_verify_us: 0,
            total_handshake_ms: 20,
            pqc_overhead_ms: 0,
            pqc_packet_size_extra: 0,
            timestamp: Utc::now(),
            is_success: true,
            pqc_fallback_reason: None,
        });
        let report = Tls13PqcWizard::analyze(&store);
        assert_eq!(report.overview.pqc_handshakes, 0);
        assert_eq!(report.overview.adoption_rate, 0.0);
        assert_eq!(report.overview.risk_score, RiskScore::Critical);
    }

    #[test]
    fn recommendations_generated_for_low_adoption() {
        let mut store = PqcHandshakeStore::new();
        store.push(PqcHandshakeRecord {
            connection_5tuple: crate::pair_correlation::FiveTuple {
                src_ip: "10.0.0.1".parse().unwrap(),
                src_port: 443, dst_ip: "10.0.0.2".parse().unwrap(),
                dst_port: 12345, protocol: 6,
            },
            tls_version: TlsVersion::TlsV1_3,
            server_name: "legacy.example.com".into(),
            client_kem_offers: vec![],
            server_kem_selected: None,
            is_hybrid_kem: false,
            classical_group: None,
            pqc_kem: None,
            shared_secret_size: 32,
            cert_sig_algorithm: SigAlgorithm::RsaPkcs1Sha256,
            is_pqc_signature: false,
            is_composite_cert: false,
            cert_chain_pqc_count: 0,
            pqc_kem_time_us: 0,
            pqc_sig_verify_us: 0,
            total_handshake_ms: 20,
            pqc_overhead_ms: 0,
            pqc_packet_size_extra: 0,
            timestamp: Utc::now(),
            is_success: true,
            pqc_fallback_reason: None,
        });
        let report = Tls13PqcWizard::analyze(&store);
        assert!(!report.recommendations.is_empty());
        assert!(report.recommendations.iter().any(|r| r.action.contains("Enable PQC")));
    }
}
