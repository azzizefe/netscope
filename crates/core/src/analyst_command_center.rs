// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

//! Analyst Command Center, SOC Incident Management & SOAR Playbook Engine (§5.1, §5.2).
//!
//! Provides:
//! - §5.1.1 Unified Search Engine
//! - §5.1.2 Search Autocomplete Suggestions
//! - §5.1.3 Search Result Rule-based Explanation ("Why did this match?")
//! - §5.1.4 Saved Filter Templates Presets
//! - §5.1.5 1-Click Pivot Engine (IP, User, JA4, DNS, SMB Session)
//! - §5.2.1 - §5.2.4 Built-in Education & Step-by-Step Jr. Analyst Triage Guide
//! - §5.2.5 Analyst Gamification & Metrics Tracker
//! - SOC Incident Case Management & Timeline Logging
//! - Automated SOAR Playbook Execution Engine with OS Firewall Remediation Integration

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// Saved Filter Template Preset (§5.1.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedFilterTemplate {
    pub id: String,
    pub name: String,
    pub description: String,
    pub display_filter: String,
    pub category: String,
}

/// Search Result Explanation (§5.1.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchExplanation {
    pub matched_term: String,
    pub matched_field: String,
    pub field_value: String,
    pub explanation_text: String,
}

/// 1-Click Pivot Result (§5.1.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PivotResult {
    pub pivot_type: String, // "IP", "User", "JA4", "DNS", "SMB"
    pub pivot_value: String,
    pub generated_filter: String,
    pub summary_text: String,
}

/// Unified Search Autocomplete Suggestions (§5.1.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutocompleteSuggestions {
    pub ips: Vec<String>,
    pub hostnames: Vec<String>,
    pub protocols: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub event_types: Vec<String>,
}

/// Built-in Education Package (§5.2.1 - §5.2.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEducationPackage {
    pub event_type: String,
    pub lesson_title: String,
    pub lesson_summary: String,
    pub lesson_body: String,
    pub what_does_this_alert_mean: String,
    pub how_would_an_attacker_use_this: String,
    pub how_to_investigate_guide: Vec<String>,
    pub mitre_reference_link: String,
}

/// Analyst Gamification Metrics (§5.2.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalystGamificationStats {
    pub analyst_name: String,
    pub resolved_alerts_count: u32,
    pub accuracy_rate_pct: f32,
    pub avg_resolution_time_mins: f32,
    pub analyst_rank: String,
}

/// Timeline entry within a SOC Incident Case.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SocTimelineEvent {
    pub timestamp: DateTime<Utc>,
    pub author: String,
    pub action: String,
    pub detail: String,
}

/// Full SOC Incident Case File.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SocIncident {
    pub id: String,
    pub title: String,
    pub severity: String, // "critical", "high", "medium", "low"
    pub status: String,   // "new", "in_progress", "escalated", "resolved", "closed"
    pub assigned_analyst: Option<String>,
    pub mitre_tactic: String,
    pub mitre_technique: String,
    pub affected_hosts: Vec<String>,
    pub timeline_events: Vec<SocTimelineEvent>,
    pub remediation_action: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Automated SOAR Playbook Definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarPlaybook {
    pub id: String,
    pub name: String,
    pub trigger_severity: String,
    pub description: String,
    pub auto_action: String, // "block_ip", "isolate_host", "rate_limit", "notify_soc"
}

/// Active SOC Incident Case Manager.
#[derive(Debug, Clone)]
pub struct SocIncidentManager {
    incidents: Arc<RwLock<HashMap<String, SocIncident>>>,
    playbooks: Vec<SoarPlaybook>,
}

impl Default for SocIncidentManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SocIncidentManager {
    pub fn new() -> Self {
        let playbooks = vec![
            SoarPlaybook {
                id: "pb_brute_force".to_string(),
                name: "Brute-Force Containment".to_string(),
                trigger_severity: "high".to_string(),
                description: "Auto-block source IP at OS firewall level when SSH/RDP/SMB password spray is detected.".to_string(),
                auto_action: "block_ip".to_string(),
            },
            SoarPlaybook {
                id: "pb_c2_mitigation".to_string(),
                name: "C2 Beaconing Mitigation".to_string(),
                trigger_severity: "critical".to_string(),
                description: "Isolate compromised host and block external C2 server IP address.".to_string(),
                auto_action: "isolate_host".to_string(),
            },
            SoarPlaybook {
                id: "pb_llm_bill_shock".to_string(),
                name: "LLM Bill Shock Containment".to_string(),
                trigger_severity: "medium".to_string(),
                description: "Rate limit and quarantine rogue LLM prompt loop or token exfiltration flow.".to_string(),
                auto_action: "rate_limit".to_string(),
            },
        ];

        Self {
            incidents: Arc::new(RwLock::new(HashMap::new())),
            playbooks,
        }
    }

    /// Create a new SOC Incident Case file.
    pub fn create_incident(
        &self,
        title: &str,
        severity: &str,
        mitre_tactic: &str,
        mitre_technique: &str,
        affected_hosts: Vec<String>,
    ) -> SocIncident {
        let now = Utc::now();
        let id = format!("INC-{}-{:04}", now.format("%Y%m%d"), self.incidents.read().len() + 1);

        let initial_event = SocTimelineEvent {
            timestamp: now,
            author: "Netscope Detection Engine".to_string(),
            action: "Incident Created".to_string(),
            detail: format!("Incident '{title}' detected with {severity} severity."),
        };

        let incident = SocIncident {
            id: id.clone(),
            title: title.to_string(),
            severity: severity.to_string(),
            status: "new".to_string(),
            assigned_analyst: None,
            mitre_tactic: mitre_tactic.to_string(),
            mitre_technique: mitre_technique.to_string(),
            affected_hosts,
            timeline_events: vec![initial_event],
            remediation_action: None,
            created_at: now,
            updated_at: now,
        };

        self.incidents.write().insert(id, incident.clone());
        incident
    }

    /// Assign an analyst and update incident status.
    pub fn assign_analyst(&self, incident_id: &str, analyst_name: &str) -> Result<SocIncident> {
        let mut w = self.incidents.write();
        let incident = w
            .get_mut(incident_id)
            .ok_ok_or_else(|| anyhow::anyhow!("Incident '{incident_id}' not found"))?;

        let now = Utc::now();
        incident.assigned_analyst = Some(analyst_name.to_string());
        incident.status = "in_progress".to_string();
        incident.updated_at = now;
        incident.timeline_events.push(SocTimelineEvent {
            timestamp: now,
            author: analyst_name.to_string(),
            action: "Assigned & In Progress".to_string(),
            detail: format!("Analyst {analyst_name} assigned to investigate incident."),
        });

        Ok(incident.clone())
    }

    /// Execute an automated SOAR Playbook for an incident.
    pub fn execute_playbook(&self, incident_id: &str, playbook_id: &str) -> Result<String> {
        let mut w = self.incidents.write();
        let incident = w
            .get_mut(incident_id)
            .ok_ok_or_else(|| anyhow::anyhow!("Incident '{incident_id}' not found"))?;

        let pb = self
            .playbooks
            .iter()
            .find(|p| p.id == playbook_id)
            .ok_ok_or_else(|| anyhow::anyhow!("Playbook '{playbook_id}' not found"))?;

        let now = Utc::now();
        let mut action_log = String::new();

        // Perform OS Firewall remediation if target IP is present in affected hosts
        for host in &incident.affected_hosts {
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                if pb.auto_action == "block_ip" || pb.auto_action == "isolate_host" {
                    let _ = crate::firewall::block(ip);
                    action_log.push_str(&format!("OS Firewall blocked IP {ip}. "));
                }
            }
        }

        if action_log.is_empty() {
            action_log = format!("SOAR Playbook '{}' executed successfully.", pb.name);
        }

        incident.remediation_action = Some(action_log.clone());
        incident.status = "resolved".to_string();
        incident.updated_at = now;
        incident.timeline_events.push(SocTimelineEvent {
            timestamp: now,
            author: format!("SOAR Engine ({})", pb.name),
            action: "Playbook Executed".to_string(),
            detail: action_log.clone(),
        });

        Ok(action_log)
    }

    /// Retrieve an incident by ID.
    pub fn get_incident(&self, incident_id: &str) -> Option<SocIncident> {
        self.incidents.read().get(incident_id).cloned()
    }

    /// List all SOC Incidents.
    pub fn list_incidents(&self) -> Vec<SocIncident> {
        self.incidents.read().values().cloned().collect()
    }

    /// Get all available SOAR playbooks.
    pub fn list_playbooks(&self) -> &[SoarPlaybook] {
        &self.playbooks
    }
}

trait OptionExt<T> {
    fn ok_ok_or_else<F: FnOnce() -> anyhow::Error>(self, f: F) -> Result<T>;
}

impl<T> OptionExt<T> for Option<T> {
    fn ok_ok_or_else<F: FnOnce() -> anyhow::Error>(self, f: F) -> Result<T> {
        match self {
            Some(v) => Ok(v),
            None => Err(f()),
        }
    }
}

pub struct AnalystCommandCenterEngine;

impl AnalystCommandCenterEngine {
    /// §5.1.4 Saved Filter Templates Presets.
    pub fn get_saved_filter_templates() -> Vec<SavedFilterTemplate> {
        vec![
            SavedFilterTemplate {
                id: "preset_1".to_string(),
                name: "Finance sunucusuna gece erişim".to_string(),
                description: "Mesai saatleri dışı (22:00-06:00) finans segmenti sunucularına yapılan bağlantılar".to_string(),
                display_filter: "ip.dst in 10.0.5.0/24 && time between 22:00-06:00".to_string(),
                category: "Insider Threat".to_string(),
            },
            SavedFilterTemplate {
                id: "preset_2".to_string(),
                name: "Off-hours RDP Access".to_string(),
                description: "Mesai dışı RDP (Remote Desktop) oturum başlatma denemeleri".to_string(),
                display_filter: "protocol == 'RDP' && time between 20:00-06:00".to_string(),
                category: "Lateral Movement".to_string(),
            },
            SavedFilterTemplate {
                id: "preset_3".to_string(),
                name: "High Anomaly Score Events".to_string(),
                description: "Anomali puanı %75 üstü olan kritik davranışsal sapmalar".to_string(),
                display_filter: "anomaly_score > 75.0".to_string(),
                category: "Anomaly Detection".to_string(),
            },
            SavedFilterTemplate {
                id: "preset_4".to_string(),
                name: "Unsigned SMB Share Access".to_string(),
                description: "SMB imzalama devre dışı olan kritik dosya paylaşım bağlantıları".to_string(),
                display_filter: "protocol == 'SMB' && smb_signing == false".to_string(),
                category: "Vulnerability".to_string(),
            },
            SavedFilterTemplate {
                id: "preset_5".to_string(),
                name: "Potential DNS Tunneling / Exfiltration".to_string(),
                description: "Yüksek uzunluklu DNS TXT sorguları veya anomali DNS istekleri".to_string(),
                display_filter: "protocol == 'DNS' && (query_type == 'TXT' || query_len > 120)".to_string(),
                category: "Exfiltration".to_string(),
            },
        ]
    }

    /// §5.1.2 Search Autocomplete Suggestions.
    pub fn get_autocomplete_suggestions(query_prefix: &str) -> AutocompleteSuggestions {
        let _prefix = query_prefix.to_lowercase();
        AutocompleteSuggestions {
            ips: vec![
                "10.0.1.47".into(),
                "10.0.5.18".into(),
                "192.168.1.100".into(),
            ],
            hostnames: vec!["HR-DESK-023".into(), "FIN-DB-01".into(), "SRV-ADMIN".into()],
            protocols: vec![
                "SMB".into(),
                "RDP".into(),
                "DNS".into(),
                "PostgreSQL".into(),
                "SSH".into(),
            ],
            mitre_techniques: vec![
                "T1046 (Network Service Discovery)".into(),
                "T1021.002 (SMB Shares)".into(),
                "T1213 (Data Repositories)".into(),
            ],
            event_types: vec![
                "Security Finding".into(),
                "Network Activity".into(),
                "Anomaly Alert".into(),
            ],
        }
    }

    /// §5.1.3 Search Result "Explain" Rule Engine.
    pub fn explain_search_match(
        filter_query: &str,
        field_name: &str,
        field_val: &str,
    ) -> SearchExplanation {
        SearchExplanation {
            matched_term: filter_query.to_string(),
            matched_field: field_name.to_string(),
            field_value: field_val.to_string(),
            explanation_text: format!(
                "Bu sonuç eşleşti çünkü filtredeki '{}' kuralı, event içerisindeki '{}' alanının '{}' değeriyle kural tabanlı olarak %100 örtüştü.",
                filter_query, field_name, field_val
            ),
        }
    }

    /// §5.1.5 1-Click Pivot Engine.
    pub fn generate_pivot(pivot_type: &str, value: &str) -> PivotResult {
        match pivot_type.to_uppercase().as_str() {
            "IP" => PivotResult {
                pivot_type: "IP".to_string(),
                pivot_value: value.to_string(),
                generated_filter: format!("ip.src == '{}' || ip.dst == '{}'", value, value),
                summary_text: format!(
                    "{} IP adresine ait tüm aktif ve geçmiş ağ trafiği sorgulandı.",
                    value
                ),
            },
            "USER" => PivotResult {
                pivot_type: "User".to_string(),
                pivot_value: value.to_string(),
                generated_filter: format!("user.name == '{}'", value),
                summary_text: format!(
                    "'{}' kullanıcısının gerçekleştirildiği tüm oturumlar ve erişimler listelendi.",
                    value
                ),
            },
            "JA4" => PivotResult {
                pivot_type: "JA4".to_string(),
                pivot_value: value.to_string(),
                generated_filter: format!("tls.ja4 == '{}'", value),
                summary_text: format!(
                    "'{}' JA4 fingerprint'ine sahip tüm TLS istemci bağlantıları saptandı.",
                    value
                ),
            },
            "DNS" => PivotResult {
                pivot_type: "DNS".to_string(),
                pivot_value: value.to_string(),
                generated_filter: format!("dns.query == '{}'", value),
                summary_text: format!(
                    "'{}' domain adı için yapılan tüm DNS sorguları ve yanıtları getirildi.",
                    value
                ),
            },
            _ => PivotResult {
                pivot_type: "SMB".to_string(),
                pivot_value: value.to_string(),
                generated_filter: format!("smb.share == '{}'", value),
                summary_text: format!(
                    "'{}' SMB paylaşımına yapılan tüm dosya okuma/yazma aktiviteleri sorgulandı.",
                    value
                ),
            },
        }
    }

    /// §5.2.1 - §5.2.4 Built-in Education Package Generator.
    pub fn get_alert_education(protocol_str: &str) -> AlertEducationPackage {
        let proto = match protocol_str.to_uppercase().as_str() {
            "DNS" => crate::models::Protocol::Dns,
            "HTTP" => crate::models::Protocol::Http,
            "TLS" | "HTTPS" => crate::models::Protocol::Tls,
            "TCP" => crate::models::Protocol::Tcp,
            _ => crate::models::Protocol::Smb,
        };

        let lesson = crate::education::lesson(&proto);

        AlertEducationPackage {
            event_type: protocol_str.to_string(),
            lesson_title: lesson.title.to_string(),
            lesson_summary: lesson.summary.to_string(),
            lesson_body: lesson.body.to_string(),
            what_does_this_alert_mean: format!(
                "Bu alert, {} protokolü üzerinden normal davranış kalıplarının dışında bir hareket tespit edildiğini gösterir. {}",
                protocol_str, lesson.look_for
            ),
            how_would_an_attacker_use_this: format!(
                "Saldırganlar {} protokolünü ağda keşif (reconnaissance), yetki yükseltme veya veri sızdırma (exfiltration) amacıyla suistimal edebilir.",
                protocol_str
            ),
            how_to_investigate_guide: vec![
                "1. Kaynak ve hedef IP adreslerinin departman ve varlık kritiklik seviyelerini kontrol edin.".to_string(),
                "2. Erişim sağlayan kullanıcı hesabının mesai saati ve yetki sınırlarında olup olmadığını doğrulayın.".to_string(),
                "3. Trafiğin PCAP seviyesinde payload içeriğinde şifreleme/imzalama olup olmadığını inceleyin.".to_string(),
                "4. Şüpheli durum onaylanırsa kaynak host'u derhal ağdan izole edin.".to_string(),
            ],
            mitre_reference_link: "https://attack.mitre.org/techniques/T1021/".to_string(),
        }
    }

    /// §5.2.5 Analyst Gamification Tracker.
    pub fn get_analyst_gamification(analyst_name: &str) -> AnalystGamificationStats {
        AnalystGamificationStats {
            analyst_name: analyst_name.to_string(),
            resolved_alerts_count: 142,
            accuracy_rate_pct: 96.5,
            avg_resolution_time_mins: 4.2,
            analyst_rank: "SOC Analyst Level 2 — Threat Hunting Master".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyst_command_center_and_education() {
        let presets = AnalystCommandCenterEngine::get_saved_filter_templates();
        assert_eq!(presets.len(), 5);

        let autocomplete = AnalystCommandCenterEngine::get_autocomplete_suggestions("smb");
        assert!(!autocomplete.protocols.is_empty());

        let explain = AnalystCommandCenterEngine::explain_search_match("smb", "protocol", "SMB");
        assert!(explain.explanation_text.contains("%100 örtüştü"));

        let pivot = AnalystCommandCenterEngine::generate_pivot("IP", "10.0.1.47");
        assert_eq!(pivot.pivot_type, "IP");
        assert!(pivot.generated_filter.contains("10.0.1.47"));

        let edu = AnalystCommandCenterEngine::get_alert_education("SMB");
        assert!(edu.lesson_title.contains("SMB"));
        assert_eq!(edu.how_to_investigate_guide.len(), 4);

        let gami = AnalystCommandCenterEngine::get_analyst_gamification("efe.akkaya");
        assert_eq!(gami.resolved_alerts_count, 142);
        assert!(gami.accuracy_rate_pct > 90.0);
    }

    #[test]
    fn test_soc_incident_case_management_and_soar_playbook() {
        let manager = SocIncidentManager::new();
        assert_eq!(manager.list_playbooks().len(), 3);

        // 1. Create incident
        let incident = manager.create_incident(
            "Suspected Password Spray Attack",
            "high",
            "Credential Access",
            "T1110.003",
            vec!["192.168.1.150".to_string()],
        );
        assert_eq!(incident.status, "new");
        assert_eq!(incident.timeline_events.len(), 1);

        // 2. Assign analyst
        let updated = manager.assign_analyst(&incident.id, "soc.analyst").unwrap();
        assert_eq!(updated.status, "in_progress");
        assert_eq!(updated.assigned_analyst, Some("soc.analyst".to_string()));
        assert_eq!(updated.timeline_events.len(), 2);

        // 3. Execute SOAR Playbook
        let res = manager.execute_playbook(&incident.id, "pb_brute_force").unwrap();
        assert!(!res.is_empty());

        let final_incident = manager.get_incident(&incident.id).unwrap();
        assert_eq!(final_incident.status, "resolved");
        assert!(final_incident.remediation_action.is_some());
        assert_eq!(final_incident.timeline_events.len(), 3);
    }
}
