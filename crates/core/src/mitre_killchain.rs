// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 azzizefe. All rights reserved.

//! 100% Offline Deterministic MITRE ATT&CK & Cyber Kill Chain Mapping Engine (§1.1.5).
//!
//! Provides zero-token mapping of network protocols, security events, and baseline anomalies to:
//! - MITRE ATT&CK Tactics & Techniques (with confidence scores: HIGH, MEDIUM, LOW)
//! - Lockheed Martin Cyber Kill Chain 7-phase mapping
//! - Multi-technique detection coverage and kill chain progression summary

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Confidence level of a MITRE ATT&CK technique mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
}

impl ConfidenceLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConfidenceLevel::High => "HIGH",
            ConfidenceLevel::Medium => "MEDIUM",
            ConfidenceLevel::Low => "LOW",
        }
    }
}

/// MITRE ATT&CK technique mapping for an event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MitreTechniqueMapping {
    pub id: String,
    pub name: String,
    pub tactic: String,
    pub confidence: ConfidenceLevel,
}

/// Cyber Kill Chain Phase mapping (1..=7).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct KillChainPhaseMapping {
    pub phase_number: u8,
    pub phase_name: String,
}

impl KillChainPhaseMapping {
    pub fn new(phase_number: u8, phase_name: impl Into<String>) -> Self {
        Self {
            phase_number: phase_number.clamp(1, 7),
            phase_name: phase_name.into(),
        }
    }
}

/// Complete Katman 5 evaluation result for an event (§1.1.5).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MitreKillChainEvaluation {
    pub techniques: Vec<MitreTechniqueMapping>,
    pub kill_chain_phases: Vec<KillChainPhaseMapping>,
    pub formatted_att_ck_summary: String,
    pub kill_chain_summary: String,
    pub detection_coverage_summary: String,
}

/// Map protocol, event summary, port, and anomaly indicators to MITRE ATT&CK & Cyber Kill Chain.
pub fn map_event_mitre_and_killchain(
    protocol: &str,
    summary: &str,
    dst_port: Option<u16>,
    has_anomaly: bool,
) -> MitreKillChainEvaluation {
    let mut techniques: Vec<MitreTechniqueMapping> = Vec::new();
    let mut phases_set: BTreeSet<(u8, String)> = BTreeSet::new();

    let proto = protocol.to_lowercase();
    let s = summary.to_lowercase();
    let port = dst_port.unwrap_or(0);

    // 1. Port scan / Service Discovery
    if s.contains("scan") || s.contains("port scan") || s.contains("discovery") {
        techniques.push(MitreTechniqueMapping {
            id: "T1046".to_string(),
            name: "Network Service Discovery".to_string(),
            tactic: "Reconnaissance".to_string(),
            confidence: ConfidenceLevel::High,
        });
        techniques.push(MitreTechniqueMapping {
            id: "T1595".to_string(),
            name: "Active Scanning".to_string(),
            tactic: "Reconnaissance".to_string(),
            confidence: ConfidenceLevel::High,
        });
        phases_set.insert((1, "Reconnaissance".to_string()));
    }

    // 2. SMB / Windows Admin Shares
    if proto == "smb" || port == 445 || s.contains("smb") || s.contains("admin share") {
        techniques.push(MitreTechniqueMapping {
            id: "T1021.002".to_string(),
            name: "SMB/Windows Admin Shares".to_string(),
            tactic: "Lateral Movement".to_string(),
            confidence: ConfidenceLevel::High,
        });
        if !techniques.iter().any(|t| t.id == "T1046") {
            techniques.push(MitreTechniqueMapping {
                id: "T1046".to_string(),
                name: "Network Service Discovery".to_string(),
                tactic: "Reconnaissance".to_string(),
                confidence: ConfidenceLevel::High,
            });
        }
        phases_set.insert((2, "Weaponization".to_string()));
        phases_set.insert((3, "Delivery".to_string()));
        phases_set.insert((7, "Actions on Objective".to_string()));
    }

    // 3. RDP
    if proto == "rdp" || port == 3389 || s.contains("rdp") {
        techniques.push(MitreTechniqueMapping {
            id: "T1021.001".to_string(),
            name: "Remote Desktop Protocol".to_string(),
            tactic: "Lateral Movement".to_string(),
            confidence: ConfidenceLevel::Medium,
        });
        if !techniques.iter().any(|t| t.id == "T1046") {
            techniques.push(MitreTechniqueMapping {
                id: "T1046".to_string(),
                name: "Network Service Discovery".to_string(),
                tactic: "Reconnaissance".to_string(),
                confidence: ConfidenceLevel::High,
            });
        }
        phases_set.insert((4, "Exploitation".to_string()));
        phases_set.insert((6, "Command and Control".to_string()));
    }

    // 4. SSH / Remote Services
    if proto == "ssh" || port == 22 || s.contains("ssh") {
        techniques.push(MitreTechniqueMapping {
            id: "T1021.004".to_string(),
            name: "SSH".to_string(),
            tactic: "Lateral Movement".to_string(),
            confidence: ConfidenceLevel::High,
        });
        phases_set.insert((4, "Exploitation".to_string()));
    }

    // 5. DNS / Tunneling
    if proto == "dns" || port == 53 {
        if s.contains("tunnel") || s.contains("exfil") || has_anomaly {
            techniques.push(MitreTechniqueMapping {
                id: "T1071.004".to_string(),
                name: "DNS Protocols".to_string(),
                tactic: "Command and Control".to_string(),
                confidence: ConfidenceLevel::High,
            });
            phases_set.insert((6, "Command and Control".to_string()));
        } else {
            techniques.push(MitreTechniqueMapping {
                id: "T1590".to_string(),
                name: "Gather Victim Network Information".to_string(),
                tactic: "Reconnaissance".to_string(),
                confidence: ConfidenceLevel::Medium,
            });
            phases_set.insert((1, "Reconnaissance".to_string()));
        }
    }

    // 6. HTTP / HTTPS / TLS C2
    if proto == "http" || proto == "tls" || port == 80 || port == 443 {
        if s.contains("beacon") || s.contains("c2") {
            techniques.push(MitreTechniqueMapping {
                id: "T1071.001".to_string(),
                name: "Web Protocols".to_string(),
                tactic: "Command and Control".to_string(),
                confidence: ConfidenceLevel::High,
            });
            phases_set.insert((6, "Command and Control".to_string()));
        } else if techniques.is_empty() {
            techniques.push(MitreTechniqueMapping {
                id: "T1071".to_string(),
                name: "Application Layer Protocol".to_string(),
                tactic: "Command and Control".to_string(),
                confidence: ConfidenceLevel::Medium,
            });
            phases_set.insert((6, "Command and Control".to_string()));
        }
    }

    // 7. Threat Intel / AbuseIPDB / URLhaus
    if s.contains("abuseipdb") || s.contains("malicious") || s.contains("urlhaus") {
        techniques.push(MitreTechniqueMapping {
            id: "T1190".to_string(),
            name: "Exploit Public-Facing Application".to_string(),
            tactic: "Initial Access".to_string(),
            confidence: ConfidenceLevel::High,
        });
        phases_set.insert((3, "Delivery".to_string()));
    }

    // 8. Exfiltration / High Entropy / Data Volume
    if s.contains("exfiltration")
        || s.contains("high entropy")
        || (has_anomaly && s.contains("transfer"))
    {
        techniques.push(MitreTechniqueMapping {
            id: "T1041".to_string(),
            name: "Exfiltration Over C2 Channel".to_string(),
            tactic: "Exfiltration".to_string(),
            confidence: ConfidenceLevel::High,
        });
        phases_set.insert((7, "Actions on Objective".to_string()));
    }

    // Fallback if no techniques matched
    if techniques.is_empty() {
        techniques.push(MitreTechniqueMapping {
            id: "T1046".to_string(),
            name: "Network Service Discovery".to_string(),
            tactic: "Reconnaissance".to_string(),
            confidence: ConfidenceLevel::Medium,
        });
        phases_set.insert((1, "Reconnaissance".to_string()));
    }

    // Deduplicate techniques by ID
    let mut seen_ids = std::collections::HashSet::new();
    techniques.retain(|t| seen_ids.insert(t.id.clone()));

    // Format ATT&CK text block matching spec
    let mut formatted_lines = vec!["MITRE ATT&CK:".to_string()];
    for t in &techniques {
        formatted_lines.push(format!(
            "  {:6} {:28} (confidence: {})",
            t.id,
            t.name,
            t.confidence.as_str()
        ));
    }
    let formatted_att_ck_summary = formatted_lines.join("\n");

    // Convert phases set to vector
    let kill_chain_phases: Vec<KillChainPhaseMapping> = phases_set
        .into_iter()
        .map(|(num, name)| KillChainPhaseMapping::new(num, name))
        .collect();

    let kill_chain_chain_str = kill_chain_phases
        .iter()
        .map(|p| format!("{} ({})", p.phase_number, p.phase_name))
        .collect::<Vec<_>>()
        .join(" → ");
    let kill_chain_summary = format!("Kill Chain Phase: {}", kill_chain_chain_str);

    let count = techniques.len();
    let detection_coverage_summary = format!(
        "Detection coverage: Bu event zinciri, {} ATT&CK tekniğini kapsıyor.",
        count
    );

    MitreKillChainEvaluation {
        techniques,
        kill_chain_phases,
        formatted_att_ck_summary,
        kill_chain_summary,
        detection_coverage_summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mitre_killchain_mapping() {
        let eval = map_event_mitre_and_killchain(
            "SMB",
            "SMB Read Request on Admin Share",
            Some(445),
            true,
        );
        assert!(!eval.techniques.is_empty());
        assert!(eval.techniques.iter().any(|t| t.id == "T1021.002"));
        assert!(eval
            .techniques
            .iter()
            .any(|t| t.confidence == ConfidenceLevel::High));
        assert!(eval.kill_chain_summary.contains("2 (Weaponization)"));
        assert!(eval
            .detection_coverage_summary
            .contains("ATT&CK tekniğini kapsıyor"));
    }

    #[test]
    fn test_rdp_and_scan_mapping() {
        let eval =
            map_event_mitre_and_killchain("RDP", "RDP Connection Attempt", Some(3389), false);
        assert!(eval.techniques.iter().any(|t| t.id == "T1021.001"));
        assert!(eval.kill_chain_summary.contains("4 (Exploitation)"));
    }
}
