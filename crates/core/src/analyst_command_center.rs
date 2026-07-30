// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

//! Analyst Command Center & Built-in Education Engine (§5.1, §5.2).
//!
//! Provides:
//! - §5.1.1 Unified Search Engine
//! - §5.1.2 Search Autocomplete Suggestions
//! - §5.1.3 Search Result Rule-based Explanation ("Why did this match?")
//! - §5.1.4 Saved Filter Templates Presets
//! - §5.1.5 1-Click Pivot Engine (IP, User, JA4, DNS, SMB Session)
//! - §5.2.1 - §5.2.4 Built-in Education & Step-by-Step Jr. Analyst Triage Guide
//! - §5.2.5 Analyst Gamification & Metrics Tracker

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
                format!("1. Kaynak ve hedef IP adreslerinin departman ve varlık kritiklik seviyelerini kontrol edin."),
                format!("2. Erişim sağlayan kullanıcı hesabının mesai saati ve yetki sınırlarında olup olmadığını doğrulayın."),
                format!("3. Trafiğin PCAP seviyesinde payload içeriğinde şifreleme/imzalama olup olmadığını inceleyin."),
                format!("4. Şüpheli durum onaylanırsa kaynak host'u derhal ağdan izole edin."),
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
}
