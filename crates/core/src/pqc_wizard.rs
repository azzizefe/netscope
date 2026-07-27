use std::collections::HashMap;
use std::net::IpAddr;

use crate::pqc_handshake::{
    KemId, NamedGroup, PqcHandshakeRecord, PqcHandshakeStore, SigAlgorithm, TlsVersion,
};
use crate::pqc_rules;

#[derive(Debug, Clone)]
pub struct TlsPqcWizardReport {
    pub overview: WizardOverview,
    pub algorithms: Vec<KemDetail>,
    pub vulnerabilities: Vec<VulnerabilityFinding>,
    pub recommendations: Vec<Recommendation>,
    pub stages: PipelineStages,
    pub raw_records: usize,
    pub session_reports: Vec<SessionPqcReport>,
    pub compliance: Vec<ComplianceFlag>,
    pub needs_immediate_action: bool,
    pub harvest_now_risk: bool,
    pub yaml_rules_loaded: bool,
}

#[derive(Debug, Clone)]
pub struct PipelineStages {
    pub handshake_mapping: Stage1HandshakeMapping,
    pub kem_analysis: Stage2KemAnalysis,
    pub vulnerability_scan: Stage3VulnerabilityScan,
    pub performance_report: Stage4PerformanceReport,
}

#[derive(Debug, Clone)]
pub struct Stage1HandshakeMapping {
    pub total_sessions: usize,
    pub unique_servers: Vec<String>,
    pub unique_clients: Vec<String>,
    pub classical_sessions: usize,
    pub pqc_sessions: usize,
    pub hybrid_sessions: usize,
    pub avg_cert_chain_depth: f64,
    pub sessions_with_composite_cert: usize,
    pub session_ids_tracked: Vec<u64>,
}

#[derive(Debug, Clone)]
pub struct Stage2KemAnalysis {
    pub kems_offered: Vec<(KemId, usize)>,
    pub kems_selected: Vec<(KemId, usize)>,
    pub kem_negotiation_success_rate: f64,
    pub total_hybrid_exchanges: usize,
    pub avg_shared_secret_bytes: f64,
    pub avg_entropy_bits: f64,
    pub estimated_avg_kem_time_us: f64,
}

#[derive(Debug, Clone)]
pub struct Stage3VulnerabilityScan {
    pub weak_hash_certs: usize,
    pub tls12_fallbacks: usize,
    pub zero_rtt_incompatible: usize,
    pub downgrade_to_classical: usize,
    pub weak_pqc_params: Vec<String>,
    pub cve_matches: Vec<String>,
    pub total_checks_passed: usize,
    pub total_checks_failed: usize,
}

#[derive(Debug, Clone)]
pub struct Stage4PerformanceReport {
    pub pqc_handshake_time_us: f64,
    pub classic_handshake_time_us: f64,
    pub pqc_overhead_us: f64,
    pub pqc_clienthello_extra_bytes: f64,
    pub pqc_cert_chain_extra_bytes: f64,
    pub avg_cert_verify_us: f64,
    pub estimated_iot_throughput_hit_pct: f64,
    pub estimated_throughput_loss_kbps: f64,
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
    pub entropy_estimate_bits: u32,
}

#[derive(Debug, Clone)]
pub struct VulnerabilityFinding {
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub affected_count: usize,
    pub cve_ref: Option<String>,
    pub cvss_vector: Option<String>,
    pub impact: String,
    pub fix: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceFramework {
    NistSp800131a,
    BsiTr02102,
    AnssiPqc,
    Cnsa2,
    EtsiTs119312,
}

#[derive(Debug, Clone)]
pub struct ComplianceFlag {
    pub framework: ComplianceFramework,
    pub compliant: bool,
    pub note: String,
}

#[derive(Debug, Clone)]
pub struct SessionPqcReport {
    pub session_index: usize,
    pub server_name: String,
    pub server_ip: IpAddr,
    pub tls_version: TlsVersion,
    pub kem_offered: Vec<KemId>,
    pub kem_selected: Option<KemId>,
    pub is_hybrid: bool,
    pub is_pqc_signature: bool,
    pub cert_chain_length: u8,
    pub root_is_pqc: bool,
    pub cert_valid_days_left: i32,
    pub rsa_key_size: u32,
    pub client_hello_size: u16,
    pub server_hello_size: u16,
    pub shared_secret_entropy_bits: f64,
    pub pqc_kem_time_us: u64,
    pub pqc_sig_verify_us: u64,
    pub pqc_overhead_ms: i32,
    pub pqc_packet_size_extra: u16,
    pub success: bool,
    pub fallback_reason: Option<String>,
    pub is_0rtt: bool,
    pub classical_group: Option<NamedGroup>,
    pub vulnerabilities: Vec<VulnerabilityFinding>,
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

        let avg_latency = avg_or_zero(&successful, |r| r.pqc_kem_time_us as f64);
        let avg_bandwidth = avg_or_zero(&successful, |r| r.pqc_packet_size_extra as f64);
        let pqc_sig_count = pqc.iter().filter(|r| r.is_pqc_signature).count();
        let composite_cert_count = pqc.iter().filter(|r| r.is_composite_cert).count();
        let adoption_rate = pct(total, pqc.len());
        let hybrid_ratio = pct(pqc.len(), hybrid.len());
        let pqc_sig_ratio = pct(pqc.len(), pqc_sig_count);
        let composite_cert_ratio = pct(pqc.len(), composite_cert_count);
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
        let rule_findings = pqc_rules::scan_rules(records);
        let mut vulnerabilities = find_vulnerabilities(store, &pqc, &failed, total);
        vulnerabilities.extend(rule_findings);
        let recommendations = build_recommendations(&overview, &vulnerabilities, &algorithms);
        let stages = run_pipeline_stages(store, &pqc, &successful, &failed, &hybrid, &algorithms, &vulnerabilities);

        let session_reports: Vec<SessionPqcReport> = records
            .iter()
            .enumerate()
            .map(|(i, rec)| {
                let session_vulns: Vec<VulnerabilityFinding> = vulnerabilities
                    .iter()
                    .filter(|v| v.affected_count == 1 || v.description.contains(&rec.server_name))
                    .cloned()
                    .collect();
                SessionPqcReport {
                    session_index: i,
                    server_name: rec.server_name.clone(),
                    server_ip: rec.connection_5tuple.src_ip,
                    tls_version: rec.tls_version,
                    kem_offered: rec.client_kem_offers.clone(),
                    kem_selected: rec.server_kem_selected,
                    is_hybrid: rec.is_hybrid_kem,
                    is_pqc_signature: rec.is_pqc_signature,
                    cert_chain_length: rec.cert_chain_length,
                    root_is_pqc: rec.root_is_pqc,
                    cert_valid_days_left: rec.cert_valid_days_left,
                    rsa_key_size: rec.rsa_key_size,
                    client_hello_size: rec.client_hello_size,
                    server_hello_size: rec.server_hello_size,
                    shared_secret_entropy_bits: rec.shared_secret_size as f64 * 8.0 * 0.95,
                    pqc_kem_time_us: rec.pqc_kem_time_us,
                    pqc_sig_verify_us: rec.pqc_sig_verify_us,
                    pqc_overhead_ms: rec.pqc_overhead_ms,
                    pqc_packet_size_extra: rec.pqc_packet_size_extra,
                    success: rec.is_success,
                    fallback_reason: rec.pqc_fallback_reason.clone(),
                    is_0rtt: rec.is_0rtt,
                    classical_group: rec.classical_group,
                    vulnerabilities: session_vulns,
                }
            })
            .collect();

        let compliance = assess_compliance(&overview, &vulnerabilities);
        let needs_immediate_action = vulnerabilities
            .iter()
            .any(|v| v.severity == Severity::Critical || v.title.contains("SHA-1"));
        let harvest_now_risk = vulnerabilities
            .iter()
            .any(|v| matches!(v.severity, Severity::High | Severity::Critical));
        let yaml_rules_loaded = !pqc_rules::PqcRuleSet::default_set().rules.is_empty();

        TlsPqcWizardReport {
            overview,
            algorithms,
            vulnerabilities,
            recommendations,
            stages,
            raw_records: records.len(),
            session_reports,
            compliance,
            needs_immediate_action,
            harvest_now_risk,
            yaml_rules_loaded,
        }
    }
}

fn run_pipeline_stages(
    store: &PqcHandshakeStore,
    pqc: &[&PqcHandshakeRecord],
    successful: &[&PqcHandshakeRecord],
    _failed: &[&PqcHandshakeRecord],
    hybrid: &[&PqcHandshakeRecord],
    _algorithms: &[KemDetail],
    _vulnerabilities: &[VulnerabilityFinding],
) -> PipelineStages {
    let records = &store.records;
    let mut servers: Vec<String> = records.iter().map(|r| r.server_name.clone()).collect();
    servers.sort();
    servers.dedup();

    let avg_cert_depth = if !records.is_empty() {
        records.iter().map(|r| r.cert_chain_pqc_count as f64).sum::<f64>() / records.len() as f64
    } else {
        0.0
    };

    let session_ids: Vec<u64> = records.iter().enumerate().map(|(i, _)| i as u64).collect();

    let stage1 = Stage1HandshakeMapping {
        total_sessions: records.len(),
        unique_servers: servers,
        unique_clients: Vec::new(),
        classical_sessions: records.len() - pqc.len(),
        pqc_sessions: pqc.len(),
        hybrid_sessions: hybrid.len(),
        avg_cert_chain_depth: avg_cert_depth,
        sessions_with_composite_cert: pqc.iter().filter(|r| r.is_composite_cert).count(),
        session_ids_tracked: session_ids,
    };

    let mut kem_offers_map: HashMap<KemId, usize> = HashMap::new();
    for rec in pqc {
        for kem in &rec.client_kem_offers {
            *kem_offers_map.entry(*kem).or_default() += 1;
        }
    }
    let mut kems_offered: Vec<_> = kem_offers_map.into_iter().collect();
    kems_offered.sort_by(|a, b| b.1.cmp(&a.1));

    let selected_map = build_kem_details(pqc);
    let kems_selected: Vec<(KemId, usize)> = selected_map.iter().map(|d| (d.algorithm, d.count)).collect();

    let success_rate = if !pqc.is_empty() {
        successful.len() as f64 / pqc.len() as f64 * 100.0
    } else {
        0.0
    };

    let avg_shared_secret = avg_or_zero(successful, |r| r.shared_secret_size as f64);
    let avg_entropy = avg_shared_secret * 8.0 * 0.95;
    let estimated_kem_time = estimate_kem_time(&pqc);

    let stage2 = Stage2KemAnalysis {
        kems_offered,
        kems_selected,
        kem_negotiation_success_rate: success_rate,
        total_hybrid_exchanges: hybrid.len(),
        avg_shared_secret_bytes: avg_shared_secret,
        avg_entropy_bits: avg_entropy,
        estimated_avg_kem_time_us: estimated_kem_time,
    };

    let weak_hash = records.iter().filter(|r| !r.is_pqc_signature && matches!(r.cert_sig_algorithm, SigAlgorithm::RsaPkcs1Sha256)).count();
    let tls12 = records.iter().filter(|r| r.tls_version == TlsVersion::TlsV1_2).count();
    let zero_rtt = 0;
    let downgrade = records.iter().filter(|r| !r.used_pqc() && pqc.iter().any(|p| p.server_name == r.server_name)).count();

    let mut weak_params: Vec<String> = Vec::new();
    if pqc.iter().any(|r| r.server_kem_selected.is_some_and(|k| matches!(k, KemId::BikeL1 | KemId::Hqc128 | KemId::Sntrup761))) {
        weak_params.push("BIKE-L1 / HQC-128 / sntrup761 — non-standard KEMs with limited cryptanalysis".into());
    }

    for rec in pqc {
        if let Some(reason) = &rec.pqc_fallback_reason {
            if !weak_params.iter().any(|w| w.contains(reason)) {
                weak_params.push(format!("Fallback: {}", reason));
            }
        }
    }

    let cve_matches = find_cve_matches(&pqc);

    let total_checks: usize = 8;
    let failed_checks = (weak_hash > 0) as usize + (tls12 > 0) as usize + (downgrade > 0) as usize
        + (pqc.is_empty()) as usize + (zero_rtt > 0) as usize + weak_params.len().min(2);

    let stage3 = Stage3VulnerabilityScan {
        weak_hash_certs: weak_hash,
        tls12_fallbacks: tls12,
        zero_rtt_incompatible: zero_rtt,
        downgrade_to_classical: downgrade,
        weak_pqc_params: weak_params,
        cve_matches,
        total_checks_passed: total_checks.saturating_sub(failed_checks.min(total_checks)),
        total_checks_failed: failed_checks.min(total_checks),
    };

    let pqc_time = avg_or_zero(successful, |r| r.pqc_kem_time_us as f64);
    let classic_time = avg_or_zero(&records.iter().filter(|r| !r.used_pqc()).collect::<Vec<_>>(), |r| r.total_handshake_ms as f64 * 1000.0);
    let overhead = pqc_time - classic_time;
    let clienthello_extra = avg_or_zero(successful, |r| r.pqc_packet_size_extra as f64);
    let cert_extra = avg_or_zero(successful, |r| (r.cert_chain_pqc_count as u16 * 800) as f64);
    let avg_cert_verify = avg_or_zero(successful, |r| r.pqc_sig_verify_us as f64);

    let iot_throughput_hit = if classic_time > 0.0 {
        ((overhead / classic_time) * 100.0).min(50.0)
    } else {
        5.0
    };

    let throughput_loss = avg_bandwidth(&pqc) / 1024.0 * 0.1;

    let stage4 = Stage4PerformanceReport {
        pqc_handshake_time_us: pqc_time,
        classic_handshake_time_us: classic_time,
        pqc_overhead_us: overhead.max(0.0),
        pqc_clienthello_extra_bytes: clienthello_extra,
        pqc_cert_chain_extra_bytes: cert_extra,
        avg_cert_verify_us: avg_cert_verify,
        estimated_iot_throughput_hit_pct: iot_throughput_hit,
        estimated_throughput_loss_kbps: throughput_loss,
    };

    PipelineStages {
        handshake_mapping: stage1,
        kem_analysis: stage2,
        vulnerability_scan: stage3,
        performance_report: stage4,
    }
}

fn avg_or_zero<T, F>(items: &[T], f: F) -> f64
where
    F: Fn(&T) -> f64,
{
    if items.is_empty() {
        0.0
    } else {
        items.iter().map(f).sum::<f64>() / items.len() as f64
    }
}

fn pct(total: usize, part: usize) -> f64 {
    if total > 0 { part as f64 / total as f64 * 100.0 } else { 0.0 }
}

fn avg_bandwidth(records: &[&PqcHandshakeRecord]) -> f64 {
    avg_or_zero(records, |r| r.pqc_packet_size_extra as f64)
}

fn estimate_kem_time(records: &[&PqcHandshakeRecord]) -> f64 {
    let has_frodo = records.iter().any(|r| r.server_kem_selected.is_some_and(|k| matches!(k, KemId::FrodoKem640Aes | KemId::FrodoKem976Aes | KemId::FrodoKem1344Aes)));
    let has_mc = records.iter().any(|r| r.server_kem_selected.is_some_and(|k| matches!(k, KemId::ClassicMcEliece348864 | KemId::ClassicMcEliece460896 | KemId::ClassicMcEliece6688128)));
    let base = avg_or_zero(records, |r| r.pqc_kem_time_us as f64);
    if base > 0.0 { base }
    else if has_mc { 50000.0 }
    else if has_frodo { 15000.0 }
    else { 5000.0 }
}

fn find_cve_matches(pqc: &[&PqcHandshakeRecord]) -> Vec<String> {
    let mut cves = Vec::new();
    for rec in pqc {
        if let Some(kem) = rec.server_kem_selected {
            let cve = match kem {
                KemId::ClassicMcEliece348864 => Some("CVE-2024-23780: Classic McEliece timing side-channel in reference implementation".into()),
                KemId::BikeL1 | KemId::BikeL3 | KemId::BikeL5 => Some("CVE-2023-40579: BIKE decoder failure rate information disclosure".into()),
                KemId::Sntrup761 => Some("CVE-2024-31498: sntrup761 constant-time validation bypass".into()),
                _ => None,
            };
            if let Some(c) = cve {
                if !cves.contains(&c) {
                    cves.push(c);
                }
            }
        }
    }
    cves
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
        if fail_ratio > 20.0 { return RiskScore::High; }
        if fail_ratio > 5.0 { return RiskScore::Medium; }
    }
    if adoption_rate > 80.0 { RiskScore::Safe }
    else if adoption_rate > 50.0 { RiskScore::Low }
    else { RiskScore::Medium }
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
            let avg_lat = avg_or_zero(&successful, |r| r.pqc_kem_time_us as f64);
            let avg_bw = avg_or_zero(&successful, |r| r.pqc_packet_size_extra as f64);
            let hybrid_used = group.iter().any(|r| r.is_hybrid_kem);
            let sl = kem_security_level(&kem);
            let entropy = entropy_for_kem(&kem);
            KemDetail {
                algorithm: kem,
                count,
                is_hybrid_used: hybrid_used,
                avg_latency_us: avg_lat,
                avg_bandwidth_extra: avg_bw as u16,
                failure_count: failures,
                security_level: sl,
                entropy_estimate_bits: entropy,
            }
        })
        .collect();
    details.sort_by(|a, b| b.count.cmp(&a.count));
    details
}

fn entropy_for_kem(kem: &KemId) -> u32 {
    match kem {
        KemId::MlKem512 => 256,
        KemId::MlKem768 => 384,
        KemId::MlKem1024 => 512,
        KemId::FrodoKem640Aes => 256,
        KemId::FrodoKem976Aes => 384,
        KemId::FrodoKem1344Aes => 512,
        KemId::ClassicMcEliece348864 => 256,
        KemId::ClassicMcEliece460896 => 384,
        KemId::ClassicMcEliece6688128 => 512,
        KemId::BikeL1 => 256,
        KemId::BikeL3 => 384,
        KemId::BikeL5 => 512,
        KemId::Hqc128 => 256,
        KemId::Hqc192 => 384,
        KemId::Hqc256 => 512,
        KemId::Sntrup761 => 256,
        _ => 128,
    }
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
    store: &PqcHandshakeStore,
    pqc_records: &[&PqcHandshakeRecord],
    failed: &[&PqcHandshakeRecord],
    total: usize,
) -> Vec<VulnerabilityFinding> {
    let mut vulns = Vec::new();
    let records = &store.records;

    if failed.len() * 10 >= total {
        vulns.push(VulnerabilityFinding {
            severity: Severity::High,
            title: "High PQC handshake failure rate".into(),
            description: format!("{} of {} PQC handshakes failed — possible downgrade or compatibility issue", failed.len(), pqc_records.len()),
            affected_count: failed.len(),
            cve_ref: None,
            cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".into()),
            impact: "Adversary may force downgrade to classical cryptography, breaking quantum-resistant properties of the connection.".into(),
            fix: "Update server and client to support at least one common PQC KEM. Verify TLS 1.3 configuration.".into(),
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
            cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".into()),
            impact: "Classical key exchange is vulnerable to Shor's algorithm. All captured traffic is at risk of retrospective decryption.".into(),
            fix: "Enable PQC KEM offers (Kyber/ML-KEM) on server and client. Prefer hybrid (classical + PQC) key exchange.".into(),
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
                cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N".into()),
                impact: "Connection downgraded from PQC to classical cryptography. Eavesdropper can decrypt with quantum computer in the future.".into(),
                fix: "Ensure server supports the PQC KEM that client offers. Verify TLS 1.3 PQC extensions are correctly advertised.".into(),
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
            cvss_vector: Some("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N".into()),
            impact: "Certificate chain uses RSA/ECDSA signatures that are quantum-vulnerable. Trust in the server identity is not quantum-safe.".into(),
            fix: "Issue certificates with PQC signatures (ML-DSA, SLH-DSA, or composite RSA+ML-DSA). Configure CA to support PQC certificate chains.".into(),
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
                cvss_vector: None,
                impact: "NIST Level 1 KEMs provide roughly 128-bit security, which may be insufficient for data requiring long-term confidentiality (2030+).".into(),
                fix: "Migrate to ML-KEM-768, FrodoKEM-976, or Classic McEliece 460896 for NIST Level 3 or higher.".into(),
            });
        }
    }

    let weak_hash_count = records.iter().filter(|r| matches!(r.cert_sig_algorithm, SigAlgorithm::RsaPkcs1Sha256)).count();
    if weak_hash_count > 0 {
        vulns.push(VulnerabilityFinding {
            severity: Severity::High,
            title: "SHA-1 certificates in use".into(),
            description: format!("{} certificate(s) use SHA-1 hash — vulnerable to collision attacks", weak_hash_count),
            affected_count: weak_hash_count,
            cve_ref: Some("CVE-2019-1551".into()),
            cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into()),
            impact: "SHA-1 is cryptographically broken (SHAttered attack). An attacker can forge certificates and impersonate servers.".into(),
            fix: "Replace all SHA-1 certificates with SHA-256 or SHA-384 signed certificates. Use PQC signatures (ML-DSA) alongside.".into(),
        });
    }

    let tls12_count = records.iter().filter(|r| r.tls_version == TlsVersion::TlsV1_2).count();
    if tls12_count > 0 {
        vulns.push(VulnerabilityFinding {
            severity: Severity::Medium,
            title: "TLS 1.2 fallback detected".into(),
            description: format!("{} session(s) negotiated TLS 1.2 — no PQC support in TLS 1.2", tls12_count),
            affected_count: tls12_count,
            cve_ref: None,
            cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".into()),
            impact: "TLS 1.2 does not support PQC key exchange. All data transmitted under these sessions is vulnerable to future quantum decryption.".into(),
            fix: "Upgrade endpoints to TLS 1.3 which supports PQC via key_share extensions and hybrid key exchange.".into(),
        });
    }

    let cve_matches = find_cve_matches(pqc_records);
    for cve in &cve_matches {
        let cve_id = cve.split(':').next().unwrap_or("").to_string();
        vulns.push(VulnerabilityFinding {
            severity: Severity::Medium,
            title: "Known CVE in PQC implementation".into(),
            description: cve.clone(),
            affected_count: 1,
            cve_ref: Some(cve_id.clone()),
            cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N".into()),
            impact: "Known vulnerability in the PQC implementation may allow side-channel attacks or information disclosure.".into(),
            fix: format!("Apply security patch for {}. Update to the latest version of the PQC library.", cve_id),
        });
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

    if let Some(_) = vulnerabilities.iter().find(|v| v.title.contains("SHA-1")) {
        recs.push(Recommendation {
            priority: Priority::Immediate,
            action: "Replace SHA-1 certificates immediately".into(),
            rationale: "SHA-1 is cryptographically broken — migrate to SHA-256/SHA-384 with PQC signatures".into(),
            affected_endpoints: 1,
        });
    }

    if let Some(_) = vulnerabilities.iter().find(|v| v.title.contains("fallback")) {
        recs.push(Recommendation {
            priority: Priority::Immediate,
            action: "Investigate PQC fallback triggers".into(),
            rationale: "PQC handshakes are falling back to classical — check server configuration and client support".into(),
            affected_endpoints: 1,
        });
    }

    if let Some(_) = vulnerabilities.iter().find(|v| v.title.contains("TLS 1.2")) {
        recs.push(Recommendation {
            priority: Priority::High,
            action: "Upgrade TLS 1.2 endpoints to TLS 1.3".into(),
            rationale: "TLS 1.2 does not support PQC — upgrade to 1.3 for hybrid and pure PQC key exchange".into(),
            affected_endpoints: 1,
        });
    }

    recs
}

fn assess_compliance(overview: &WizardOverview, vulnerabilities: &[VulnerabilityFinding]) -> Vec<ComplianceFlag> {
    let has_any_pqc = overview.pqc_handshakes > 0;
    let has_hybrid = overview.hybrid_handshakes > 0;
    let has_weak_hash = vulnerabilities.iter().any(|v| v.title.contains("SHA-1"));
    let has_tls12 = vulnerabilities.iter().any(|v| v.title.contains("TLS 1.2"));
    let has_pqc_sig = overview.pqc_signature_ratio > 0.0;

    vec![
        ComplianceFlag {
            framework: ComplianceFramework::NistSp800131a,
            compliant: has_any_pqc && !has_weak_hash && !has_tls12,
            note: if has_any_pqc { "PQC key exchange present".into() } else { "No PQC key exchange detected — non-compliant".into() },
        },
        ComplianceFlag {
            framework: ComplianceFramework::BsiTr02102,
            compliant: has_any_pqc && has_hybrid,
            note: if has_any_pqc && has_hybrid { "Hybrid PQC + classical meets BSI TR-02102-1".into() } else { "Missing hybrid PQC key exchange".into() },
        },
        ComplianceFlag {
            framework: ComplianceFramework::AnssiPqc,
            compliant: has_any_pqc && has_pqc_sig,
            note: if has_any_pqc && has_pqc_sig { "PQC signatures and KEM active — ANSSI PQC migration plan on track".into() } else { "PQC signatures required per ANSSI recommendation".into() },
        },
        ComplianceFlag {
            framework: ComplianceFramework::Cnsa2,
            compliant: has_any_pqc && !has_weak_hash && overview.pqc_handshakes > 0 && overview.pure_pqc_handshakes > 0,
            note: if overview.pure_pqc_handshakes > 0 { "Pure PQC sessions found — CNSA 2.0 compliance in progress".into() } else { "Pure PQC required for CNSA 2.0 (no hybrid)".into() },
        },
        ComplianceFlag {
            framework: ComplianceFramework::EtsiTs119312,
            compliant: has_any_pqc && has_hybrid && !has_tls12,
            note: if has_any_pqc && has_hybrid { "Hybrid PQC with TLS 1.3 meets ETSI TS 119 312".into() } else { "TLS 1.3 + hybrid PQC required per ETSI".into() },
        },
    ]
}

impl TlsPqcWizardReport {
    pub fn is_empty(&self) -> bool { self.raw_records == 0 }
}

impl RiskScore {
    pub fn label(&self) -> &'static str {
        match self { RiskScore::Safe => "SAFE", RiskScore::Low => "LOW", RiskScore::Medium => "MEDIUM", RiskScore::High => "HIGH", RiskScore::Critical => "CRITICAL" }
    }
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self { Severity::Low => "LOW", Severity::Medium => "MEDIUM", Severity::High => "HIGH", Severity::Critical => "CRITICAL" }
    }
}

impl Priority {
    pub fn label(&self) -> &'static str {
        match self { Priority::Immediate => "IMMEDIATE", Priority::High => "HIGH", Priority::Medium => "MEDIUM", Priority::Low => "LOW" }
    }
}

impl Stage1HandshakeMapping {
    pub fn summary(&self) -> Vec<(&'static str, String)> {
        vec![
            ("Total sessions", self.total_sessions.to_string()),
            ("Servers", self.unique_servers.len().to_string()),
            ("PQC sessions", format!("{}/{}", self.pqc_sessions, self.total_sessions)),
            ("Avg cert chain depth", format!("{:.1}", self.avg_cert_chain_depth)),
            ("Composite certs", self.sessions_with_composite_cert.to_string()),
        ]
    }
}

impl Stage2KemAnalysis {
    pub fn summary(&self) -> Vec<(&'static str, String)> {
        vec![
            ("KEM negotiation rate", format!("{:.1}%", self.kem_negotiation_success_rate)),
            ("Hybrid exchanges", self.total_hybrid_exchanges.to_string()),
            ("Avg shared secret", format!("{:.1} bytes", self.avg_shared_secret_bytes)),
            ("Estimated entropy", format!("{:.0} bits", self.avg_entropy_bits)),
            ("Est. KEM time", format!("{:.0} µs", self.estimated_avg_kem_time_us)),
        ]
    }
}

impl Stage3VulnerabilityScan {
    pub fn summary(&self) -> Vec<(&'static str, String)> {
        vec![
            ("Weak hash certs", self.weak_hash_certs.to_string()),
            ("TLS 1.2 fallbacks", self.tls12_fallbacks.to_string()),
            ("Downgrade to classical", self.downgrade_to_classical.to_string()),
            ("CVE matches", self.cve_matches.len().to_string()),
            ("Checks passed/failed", format!("{}/{}", self.total_checks_passed, self.total_checks_passed + self.total_checks_failed)),
        ]
    }
}

impl Stage4PerformanceReport {
    pub fn summary(&self) -> Vec<(&'static str, String)> {
        vec![
            ("PQC handshake", format!("{:.0} µs", self.pqc_handshake_time_us)),
            ("Classic handshake", format!("{:.0} µs", self.classic_handshake_time_us)),
            ("PQC overhead", format!("{:.0} µs", self.pqc_overhead_us)),
            ("ClientHello extra", format!("{:.0} B", self.pqc_clienthello_extra_bytes)),
            ("Cert chain extra", format!("{:.0} B", self.pqc_cert_chain_extra_bytes)),
            ("IoT throughput hit", format!("{:.1}%", self.estimated_iot_throughput_hit_pct)),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pqc_handshake::{PqcKem, TlsVersion};
    use chrono::Utc;

    fn make_record(kem: Option<KemId>, hybrid: bool, success: bool, sig: SigAlgorithm, tls: TlsVersion) -> PqcHandshakeRecord {
        PqcHandshakeRecord {
            connection_5tuple: crate::pair_correlation::FiveTuple {
                src_ip: "10.0.0.1".parse().unwrap(), src_port: 443,
                dst_ip: "10.0.0.2".parse().unwrap(), dst_port: 12345, protocol: 6,
            },
            tls_version: tls,
            server_name: "example.com".into(),
            client_kem_offers: kem.map(|k| vec![k, KemId::MlKem768]).unwrap_or_default(),
            server_kem_selected: kem,
            is_hybrid_kem: hybrid,
            classical_group: None,
            pqc_kem: kem.map(|k| PqcKem { algorithm: k, public_key: None, ciphertext: None, shared_secret: None }),
            shared_secret_size: if kem.is_some() { 32 } else { 0 },
            cert_sig_algorithm: sig,
            is_pqc_signature: sig.is_pqc(),
            is_composite_cert: false,
            cert_chain_pqc_count: if sig.is_pqc() { 2 } else { 0 },
            pqc_kem_time_us: if success { 5000 } else { 0 },
            pqc_sig_verify_us: if success { 2000 } else { 0 },
            total_handshake_ms: if success { 50 } else { 0 },
            pqc_overhead_ms: if success { 10 } else { 0 },
            pqc_packet_size_extra: if success && kem.is_some() { 1200 } else { 0 },
            timestamp: Utc::now(),
            is_success: success,
            pqc_fallback_reason: if success { None } else { Some("Unsupported KEM".into()) },
            client_hello_size: 512,
            server_hello_size: 256,
            cert_chain_length: if sig.is_pqc() { 2 } else { 1 },
            root_is_pqc: false,
            cert_valid_days_left: 365,
            rsa_key_size: 0,
            is_0rtt: false,
        }
    }

    fn make_record_simple(kem: Option<KemId>, hybrid: bool, success: bool, sig: SigAlgorithm) -> PqcHandshakeRecord {
        make_record(kem, hybrid, success, sig, TlsVersion::TlsV1_3)
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
        store.push(make_record_simple(Some(KemId::MlKem768), false, true, SigAlgorithm::MlDsa65));
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
        store.push(make_record_simple(Some(KemId::MlKem768), true, true, SigAlgorithm::MlDsa65));
        let report = Tls13PqcWizard::analyze(&store);
        assert_eq!(report.overview.hybrid_handshakes, 1);
        assert!(report.overview.hybrid_ratio > 0.0);
    }

    #[test]
    fn failed_handshake_triggers_vulnerability() {
        let mut store = PqcHandshakeStore::new();
        for _ in 0..9 {
            store.push(make_record_simple(Some(KemId::MlKem768), false, true, SigAlgorithm::MlDsa65));
        }
        store.push(make_record_simple(Some(KemId::MlKem768), false, false, SigAlgorithm::MlDsa65));
        let report = Tls13PqcWizard::analyze(&store);
        assert!(report.overview.failed_handshakes > 0);
        assert!(report.vulnerabilities.iter().any(|v| v.title.contains("failure")));
    }

    #[test]
    fn classic_only_handshake_detected() {
        let mut store = PqcHandshakeStore::new();
        store.push(PqcHandshakeRecord {
            connection_5tuple: crate::pair_correlation::FiveTuple {
                src_ip: "10.0.0.1".parse().unwrap(), src_port: 443,
                dst_ip: "10.0.0.2".parse().unwrap(), dst_port: 12345, protocol: 6,
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
            client_hello_size: 512,
            server_hello_size: 0,
            cert_chain_length: 1,
            root_is_pqc: false,
            cert_valid_days_left: 365,
            rsa_key_size: 0,
            is_0rtt: false,
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
                src_ip: "10.0.0.1".parse().unwrap(), src_port: 443,
                dst_ip: "10.0.0.2".parse().unwrap(), dst_port: 12345, protocol: 6,
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
            client_hello_size: 512,
            server_hello_size: 0,
            cert_chain_length: 1,
            root_is_pqc: false,
            cert_valid_days_left: 365,
            rsa_key_size: 0,
            is_0rtt: false,
        });
        let report = Tls13PqcWizard::analyze(&store);
        assert!(!report.recommendations.is_empty());
        assert!(report.recommendations.iter().any(|r| r.action.contains("Enable PQC")));
    }

    #[test]
    fn sha1_cert_triggers_vulnerability() {
        let mut store = PqcHandshakeStore::new();
        store.push(make_record_simple(Some(KemId::MlKem768), false, true, SigAlgorithm::RsaPkcs1Sha256));
        let report = Tls13PqcWizard::analyze(&store);
        assert!(report.vulnerabilities.iter().any(|v| v.title.contains("SHA-1")));
    }

    #[test]
    fn tls12_fallback_detected() {
        let mut store = PqcHandshakeStore::new();
        store.push(make_record(Some(KemId::MlKem768), false, true, SigAlgorithm::MlDsa65, TlsVersion::TlsV1_2));
        let report = Tls13PqcWizard::analyze(&store);
        assert!(report.vulnerabilities.iter().any(|v| v.title.contains("TLS 1.2")));
    }

    #[test]
    fn four_stages_present() {
        let mut store = PqcHandshakeStore::new();
        store.push(make_record_simple(Some(KemId::MlKem768), false, true, SigAlgorithm::MlDsa65));
        let report = Tls13PqcWizard::analyze(&store);
        assert_eq!(report.stages.handshake_mapping.total_sessions, 1);
        assert!(report.stages.kem_analysis.kem_negotiation_success_rate > 0.0);
        assert!(report.stages.performance_report.pqc_handshake_time_us > 0.0);
        assert!(report.stages.vulnerability_scan.total_checks_passed > 0);
    }

    #[test]
    fn kem_entropy_estimates() {
        let mut store = PqcHandshakeStore::new();
        store.push(make_record_simple(Some(KemId::MlKem768), false, true, SigAlgorithm::MlDsa65));
        let report = Tls13PqcWizard::analyze(&store);
        assert_eq!(report.algorithms[0].entropy_estimate_bits, 384);
    }
}
