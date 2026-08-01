// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

//! Visual MITRE ATT&CK Matrix & Attack Progression Engine (ROADMAP §7.2).
//!
//! Organizes mapped MITRE ATT&CK techniques across the 14 Enterprise ATT&CK Tactics
//! and formats structured 2D matrices, JSON models, and Markdown summaries for SOC dashboards.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::mitre_killchain::{ConfidenceLevel, MitreKillChainEvaluation, MitreTechniqueMapping};

/// Official MITRE ATT&CK Enterprise Tactics.
pub const MITRE_TACTICS: &[(&str, &str)] = &[
    ("TA0043", "Reconnaissance"),
    ("TA0042", "Resource Development"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
];

/// Grouped MITRE ATT&CK techniques for a single tactic column.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTacticColumn {
    pub tactic_id: String,
    pub tactic_name: String,
    pub techniques: Vec<MitreTechniqueMapping>,
}

/// Complete 2D MITRE ATT&CK Attack Matrix for SOC visualization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreAttackMatrix {
    pub columns: Vec<MitreTacticColumn>,
    pub total_techniques_detected: usize,
    pub high_confidence_count: usize,
    pub formatted_matrix_markdown: String,
}

/// Build a structured MITRE ATT&CK Attack Matrix from Katman 5 evaluations.
pub fn build_mitre_matrix(evaluations: &[MitreKillChainEvaluation]) -> MitreAttackMatrix {
    // Map tactic name -> techniques
    let mut tactic_map: BTreeMap<String, Vec<MitreTechniqueMapping>> = BTreeMap::new();
    let mut total_techniques = 0;
    let mut high_conf_count = 0;

    for eval in evaluations {
        for tech in &eval.techniques {
            total_techniques += 1;
            if tech.confidence == ConfidenceLevel::High {
                high_conf_count += 1;
            }

            let entry = tactic_map.entry(tech.tactic.clone()).or_default();

            // Avoid duplicate technique IDs within the same column
            if !entry.iter().any(|t| t.id == tech.id) {
                entry.push(tech.clone());
            }
        }
    }

    let mut columns = Vec::new();
    for (tactic_id, tactic_name) in MITRE_TACTICS {
        let tech_list = tactic_map.get(*tactic_name).cloned().unwrap_or_default();

        columns.push(MitreTacticColumn {
            tactic_id: tactic_id.to_string(),
            tactic_name: tactic_name.to_string(),
            techniques: tech_list,
        });
    }

    let formatted_markdown = format_matrix_as_markdown(&columns);

    MitreAttackMatrix {
        columns,
        total_techniques_detected: total_techniques,
        high_confidence_count: high_conf_count,
        formatted_matrix_markdown: formatted_markdown,
    }
}

fn format_matrix_as_markdown(columns: &[MitreTacticColumn]) -> String {
    let mut md = String::new();
    md.push_str("# MITRE ATT&CK® Enterprise Coverage Matrix\n\n");
    md.push_str("| Tactic ID | Tactic Name | Mapped Techniques |\n");
    md.push_str("|:---|:---|:---|\n");

    for col in columns {
        if col.techniques.is_empty() {
            md.push_str(&format!(
                "| `{}` | {} | *None* |\n",
                col.tactic_id, col.tactic_name
            ));
        } else {
            let tech_strs: Vec<String> = col
                .techniques
                .iter()
                .map(|t| format!("**{}** ({}) [{}]", t.id, t.name, t.confidence.as_str()))
                .collect();
            md.push_str(&format!(
                "| `{}` | {} | {} |\n",
                col.tactic_id,
                col.tactic_name,
                tech_strs.join(", ")
            ));
        }
    }

    md
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mitre_killchain::map_event_mitre_and_killchain;

    #[test]
    fn test_build_mitre_matrix() {
        let eval1 =
            map_event_mitre_and_killchain("smb", "smb admin share connect", Some(445), true);
        let eval2 = map_event_mitre_and_killchain("tcp", "port scan detected", Some(80), true);

        let matrix = build_mitre_matrix(&[eval1, eval2]);
        assert!(matrix.total_techniques_detected > 0);
        assert!(!matrix.formatted_matrix_markdown.is_empty());
        assert!(matrix.formatted_matrix_markdown.contains("Reconnaissance"));
    }
}
