// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 azzizefe. All rights reserved.

//! Operational Documentation, Hardware Sizing & Runbook Library Engine (§10.1).
//!
//! Provides:
//! - SOC Admin Guide manual generator (§10.1.1)
//! - SOC Analyst Playbook manual generator (§10.1.2)
//! - Rule Writing & False Positive Reduction Guide generator (§10.1.3)
//! - OpenAPI 3.1 Specification generator (§10.1.4)
//! - Incident Response Runbook Library catalog (§10.1.5)
//! - Architecture Decision Records (ADR) catalog (§10.1.6)
//! - Hardware Sizing Calculator (CPU/RAM/Disk/Bandwidth) (§10.1.7)

/// Hardware Sizing Recommendation (§10.1.7).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HardwareSizingRecommendation {
    pub events_per_sec: u64,
    pub recommended_cpu_cores: usize,
    pub recommended_ram_gb: usize,
    pub recommended_ssd_storage_gb: u64,
    pub recommended_bandwidth_mbps: u32,
}

/// Incident Response Runbook (§10.1.5).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IncidentRunbook {
    pub alert_type: String,
    pub severity: String,
    pub triage_steps: Vec<String>,
    pub containment_steps: Vec<String>,
    pub eradication_steps: Vec<String>,
}

/// Architecture Decision Record (ADR) (§10.1.6).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ArchitectureDecisionRecord {
    pub id: usize,
    pub title: String,
    pub status: String,
    pub context: String,
    pub decision: String,
    pub consequences: String,
}

/// Operational Documentation Engine (§10.1).
#[derive(Debug, Default)]
pub struct OpDocsEngine;

impl OpDocsEngine {
    pub fn new() -> Self {
        Self
    }

    /// Generate SOC Admin Guide (§10.1.1).
    pub fn generate_admin_guide(&self) -> String {
        r#"# Netscope SOC Administrator Guide
## 1. Installation & Cluster Setup
- Deploy using Docker Compose (`docker compose up -d`) or Kubernetes Helm Chart.
## 2. High Availability & Backup
- Enable Active-Active Keepalived state tracking on port 50051.
- Perform single-tenant data exports via `TenantBackupPackage`.
## 3. Troubleshooting
- Inspect audit logs via `TamperProofAuditLogger`.
"#
        .to_string()
    }

    /// Generate SOC Analyst Playbook (§10.1.2).
    pub fn generate_analyst_playbook(&self) -> String {
        r#"# Netscope SOC Analyst Playbook
## 1. Alert Triage
- Review deterministic risk score (0-100) and MITRE ATT&CK mapping.
## 2. Incident Response Workflow
- Step 1: Validate payload mask / PII protection.
- Step 2: Correlate cross-sensor events using narrative engine.
## 3. Threat Hunting
- Query ClickHouse/TimescaleDB analytical storage driver.
"#
        .to_string()
    }

    /// Generate Rule Writing Guide (§10.1.3).
    pub fn generate_rule_writing_guide(&self) -> String {
        r#"# Netscope Rule Writing & False Positive Reduction Guide
- Use exact field filters (`ip.src == 10.0.0.1 && tcp.port == 80`).
- Apply rate thresholding (`threshold: count 10, seconds 60`).
- Avoid bare substring matching on headers.
"#
        .to_string()
    }

    /// Generate OpenAPI 3.1 Specification (§10.1.4).
    pub fn generate_openapi_spec(&self) -> String {
        r#"{"openapi": "3.1.0", "info": {"title": "Netscope SOC API", "version": "1.0.0"}}"#
            .to_string()
    }

    /// Get Incident Runbook Library (§10.1.5).
    pub fn get_runbook_library(&self) -> Vec<IncidentRunbook> {
        vec![
            IncidentRunbook {
                alert_type: "C2_Beaconing".to_string(),
                severity: "CRITICAL".to_string(),
                triage_steps: vec![
                    "Identify source host IP".into(),
                    "Check beacon interval consistency".into(),
                ],
                containment_steps: vec![
                    "Isolate host via firewall rule".into(),
                    "Revoke user API tokens".into(),
                ],
                eradication_steps: vec!["Reimage compromised host".into()],
            },
            IncidentRunbook {
                alert_type: "Ransomware_SMB_Spread".to_string(),
                severity: "CRITICAL".to_string(),
                triage_steps: vec!["Detect SMB port 445 traffic spike".into()],
                containment_steps: vec!["Block port 445 on VLAN segment".into()],
                eradication_steps: vec!["Restore files from offline snapshot".into()],
            },
        ]
    }

    /// Get Architecture Decision Records (§10.1.6).
    pub fn get_adrs(&self) -> Vec<ArchitectureDecisionRecord> {
        vec![ArchitectureDecisionRecord {
            id: 1,
            title: "Zero-Token Offline Local Processing".to_string(),
            status: "APPROVED".to_string(),
            context:
                "External LLM APIs introduce latency, recurring costs, and cloud privacy concerns."
                    .to_string(),
            decision: "Implement 100% offline Rust heuristics for triage, correlation, and stats."
                .to_string(),
            consequences:
                "Zero cloud API token cost, deterministic execution, ultra-low memory footprint."
                    .to_string(),
        }]
    }

    /// Calculate Hardware Sizing (§10.1.7).
    pub fn calculate_hardware_sizing(
        &self,
        target_events_per_sec: u64,
    ) -> HardwareSizingRecommendation {
        let cores = ((target_events_per_sec / 25_000) + 2) as usize;
        let ram = ((target_events_per_sec / 12_500) + 4) as usize;
        let storage = (target_events_per_sec * 86400 * 7 * 500) / 1_000_000_000; // 7 days retention
        let bandwidth = ((target_events_per_sec * 500 * 8) / 1_000_000) as u32;

        HardwareSizingRecommendation {
            events_per_sec: target_events_per_sec,
            recommended_cpu_cores: cores.max(2),
            recommended_ram_gb: ram.max(4),
            recommended_ssd_storage_gb: storage.max(100),
            recommended_bandwidth_mbps: bandwidth.max(10),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guides_and_openapi() {
        let engine = OpDocsEngine::new();
        assert!(engine
            .generate_admin_guide()
            .contains("Administrator Guide"));
        assert!(engine
            .generate_analyst_playbook()
            .contains("Analyst Playbook"));
        assert!(engine
            .generate_rule_writing_guide()
            .contains("False Positive"));
        assert!(engine.generate_openapi_spec().contains("3.1.0"));
    }

    #[test]
    fn test_runbooks_and_adrs() {
        let engine = OpDocsEngine::new();
        let runbooks = engine.get_runbook_library();
        assert_eq!(runbooks.len(), 2);
        assert_eq!(runbooks[0].alert_type, "C2_Beaconing");

        let adrs = engine.get_adrs();
        assert_eq!(adrs.len(), 1);
        assert_eq!(adrs[0].title, "Zero-Token Offline Local Processing");
    }

    #[test]
    fn test_hardware_sizing() {
        let engine = OpDocsEngine::new();
        let sizing = engine.calculate_hardware_sizing(100_000);
        assert!(sizing.recommended_cpu_cores >= 6);
        assert!(sizing.recommended_ram_gb >= 12);
        assert!(sizing.recommended_ssd_storage_gb >= 100);
    }
}
