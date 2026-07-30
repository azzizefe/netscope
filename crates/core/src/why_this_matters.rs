// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 azzizefe. All rights reserved.

//! 100% Offline Deterministic "Why This Matters" & Action Recommendation Engine (§1.1.7).
//!
//! Provides zero-token, zero-LLM template-based explanation and rule-based action guidance:
//! - Pre-written template library for event types and severity levels
//! - Template interpolation (no LLM, no API cost, 100% deterministic)
//! - Rule-based 1-2-3 step actionable response catalog

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Pre-defined Action Recommendation in response catalog (§1.1.7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRecommendation {
    pub step_number: u8,
    pub title: String,
    pub instruction: String,
}

/// Result of Katman 7 "Why This Matters" evaluation (§1.1.7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhyThisMattersEvaluation {
    pub why_this_matters_paragraph: String,
    pub recommended_actions: Vec<ActionRecommendation>,
    pub formatted_actions_text: String,
    pub formatted_full_block: String,
}

/// Template context variables for interpolation.
#[derive(Debug, Clone, Default)]
pub struct TemplateContext {
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_host: String,
    pub department: String,
    pub protocol: String,
    pub severity: String,
    pub anomaly_reasons: String,
    pub asset_type: String,
}

/// Template item in the catalog.
#[derive(Debug, Clone)]
pub struct ExplanationTemplate {
    pub key: String,
    pub pattern: String,
    pub action_steps: Vec<(String, String)>,
}

/// Why This Matters Engine & Template Catalog (§1.1.7).
#[derive(Debug, Clone)]
pub struct WhyThisMattersEngine {
    pub templates: HashMap<String, ExplanationTemplate>,
}

impl Default for WhyThisMattersEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl WhyThisMattersEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            templates: HashMap::new(),
        };
        engine.init_default_catalog();
        engine
    }

    fn init_default_catalog(&mut self) {
        // 1. SMB / Admin Shares
        self.templates.insert(
            "smb_critical".to_string(),
            ExplanationTemplate {
                key: "smb_critical".to_string(),
                pattern: "Bu event zinciri, bir iç tehdit (insider threat) veya ele geçirilmiş bir workstation'ın ({src_ip}) kritik finansal verilere ({dst_host}) erişmeye çalıştığını gösteriyor.\n\nNormalde {department} departmanından hiçbir çalışan {dst_host} veritabanına erişmez. {anomaly_reasons}\nSMB imzalama kapalı olduğu için, ağdaki bir saldırgan bu trafiği relay edebilir.".to_string(),
                action_steps: vec![
                    ("İzole Edin".to_string(), "Bu host'u ({src_ip}) hemen izole edin.".to_string()),
                    ("Şifre Sıfırlayın".to_string(), "Kullanıcının şifresini sıfırlayın.".to_string()),
                    ("SMB Signing Zorunlu Kılın".to_string(), "SMB signing'i tüm domain'de zorunlu hale getirin.".to_string()),
                ],
            },
        );

        // 2. RDP / Remote Desktop
        self.templates.insert(
            "rdp_high".to_string(),
            ExplanationTemplate {
                key: "rdp_high".to_string(),
                pattern: "Bu hareket, yetkisiz bir RDP (Remote Desktop Protocol) uzaktan erişim veya brute-force denemesi olduğunu gösteriyor.\n\nYetkisiz RDP erişimleri, saldırganların ağda yatayda ilerlemesine (lateral movement) ve sunucularda komut çalıştırmasına izin verir. {anomaly_reasons}".to_string(),
                action_steps: vec![
                    ("RDP Portunu Kapatın".to_string(), "Dışa açık RDP (3389) portlarını kapatın veya VPN arkasına alın.".to_string()),
                    ("NLA Aktifleştirin".to_string(), "Network Level Authentication (NLA) zorunlu hale getirin.".to_string()),
                    ("Oturum Kilitleme".to_string(), "Hatalı şifre denemeleri için hesap kilitleme politikasını devreye alın.".to_string()),
                ],
            },
        );

        // 3. SSH / Lateral Movement
        self.templates.insert(
            "ssh_high".to_string(),
            ExplanationTemplate {
                key: "ssh_high".to_string(),
                pattern: "Sunucular arasında şüpheli SSH bağlantısı tespit edildi.\n\nSaldırganlar ele geçirdikleri kimlik bilgileriyle kritik altyapı sunucularına ({dst_host}) erişmeye çalışıyor olabilir. {anomaly_reasons}".to_string(),
                action_steps: vec![
                    ("Bastion Host Zorunlu Yapın".to_string(), "Doğrudan SSH erişimini engelleyin, Bastion host kullanımını zorunlu tutun.".to_string()),
                    ("SSH Key Denetimi".to_string(), "Authorized_keys dosyalarını ve SSH anahtar yetkilerini denetleyin.".to_string()),
                    ("MFA Ekleme".to_string(), "SSH girişlerine 2FA/MFA doğrulaması ekleyin.".to_string()),
                ],
            },
        );

        // 4. DNS Tunneling / Exfiltration
        self.templates.insert(
            "dns_tunnel".to_string(),
            ExplanationTemplate {
                key: "dns_tunnel".to_string(),
                pattern: "Bu event, DNS protokolü üzerinden veri sızdırma (DNS Tunneling / Exfiltration) veya C2 haberleşmesi yapıldığını gösteriyor.\n\nKlasik güvenlik duvarlarını atlatmak için DNS TXT/NULL kayıtları suistimal ediliyor olabilir. {anomaly_reasons}".to_string(),
                action_steps: vec![
                    ("Zararlı Domaini Engelleyin".to_string(), "Sorgulanan zararlı DNS domainini iç DNS sunucularında Sinkhole yapın.".to_string()),
                    ("DNS Güvenlik Duvarı Devreye Alın".to_string(), "İç sunucuların dış DNS sunuculara doğrudan erişimini engelleyin (yalnızca yetkili Resolver).".to_string()),
                    ("Host Analizi".to_string(), "Kaynak host ({src_ip}) üzerinde zararlı process ve servis taraması yapın.".to_string()),
                ],
            },
        );

        // 5. Port Scan / Reconnaissance
        self.templates.insert(
            "scan_medium".to_string(),
            ExplanationTemplate {
                key: "scan_medium".to_string(),
                pattern: "Ağda aktif servis ve port taraması (Reconnaissance) tespit edildi.\n\nSaldırgan veya zararlı yazılım, sızma öncesinde açık portları ve zafiyetli servisleri keşfetmeye çalışıyor. {anomaly_reasons}".to_string(),
                action_steps: vec![
                    ("Kaynak IP'yi Engelleyin".to_string(), "Taramayı gerçekleştiren kaynak IP'yi ({src_ip}) güvenlik duvarından engelleyin.".to_string()),
                    ("Açık Portları Kapatın".to_string(), "Kullanılmayan ağ servislerini ve açık portları kapatın.".to_string()),
                    ("IDS/IPS Kural Güncelleme".to_string(), "Port tarama tespiti için IPS kurallarının aktifliğini doğrulayın.".to_string()),
                ],
            },
        );

        // 6. Generic / Default Template
        self.templates.insert(
            "generic_default".to_string(),
            ExplanationTemplate {
                key: "generic_default".to_string(),
                pattern: "Bu güvenlik anomalisi, {src_ip} kaynaklı trafikte beklenmeyen davranış veya zafiyet şüphesi olduğunu gösteriyor.\n\nKritik varlıklara ({dst_host}) yapılan bu erişim, güvenlik politikasını ihlal ediyor olabilir. {anomaly_reasons}".to_string(),
                action_steps: vec![
                    ("Trafiği İncelenmeli".to_string(), "Kaynak ({src_ip}) ve Hedef ({dst_host}) arasındaki trafiği PCAP seviyesinde inceleyin.".to_string()),
                    ("Kullanıcı Yetkilerini Doğrulayın".to_string(), "Erişimi sağlayan hesabın yetki seviyesini ve erişim gereksinimini doğrulayın.".to_string()),
                    ("Log Kayıtlarını Kontrol Edin".to_string(), "İlgili sunucudaki sistem ve güvenlik loglarını (Event Viewer / Syslog) kontrol edin.".to_string()),
                ],
            },
        );
    }

    /// Select matching template key based on protocol/event_type and severity.
    fn select_template_key(&self, protocol: &str, _severity: &str, summary: &str) -> String {
        let p = protocol.to_lowercase();
        let s = summary.to_lowercase();

        if p == "smb" || s.contains("smb") {
            "smb_critical".to_string()
        } else if p == "rdp" || s.contains("rdp") {
            "rdp_high".to_string()
        } else if p == "ssh" || s.contains("ssh") {
            "ssh_high".to_string()
        } else if p == "dns"
            && (s.contains("tunnel") || s.contains("exfil") || s.contains("anomaly"))
        {
            "dns_tunnel".to_string()
        } else if s.contains("scan") || s.contains("discovery") {
            "scan_medium".to_string()
        } else {
            "generic_default".to_string()
        }
    }

    /// Render "Why This Matters" evaluation for an event (§1.1.7).
    pub fn evaluate(&self, ctx: &TemplateContext) -> WhyThisMattersEvaluation {
        let template_key =
            self.select_template_key(&ctx.protocol, &ctx.severity, &ctx.anomaly_reasons);
        let template = self
            .templates
            .get(&template_key)
            .unwrap_or_else(|| self.templates.get("generic_default").unwrap());

        let dst_display = if ctx.dst_host.is_empty() {
            ctx.dst_ip.clone()
        } else {
            ctx.dst_host.clone()
        };

        let dept_display = if ctx.department.is_empty() {
            "HR".to_string()
        } else {
            ctx.department.clone()
        };

        let anomaly_text = if ctx.anomaly_reasons.is_empty() {
            "".to_string()
        } else {
            format!("\n{}", ctx.anomaly_reasons)
        };

        // Interpolate paragraph (zero-token, template-based)
        let paragraph = template
            .pattern
            .replace("{src_ip}", &ctx.src_ip)
            .replace("{dst_ip}", &ctx.dst_ip)
            .replace("{dst_host}", &dst_display)
            .replace("{department}", &dept_display)
            .replace("{protocol}", &ctx.protocol)
            .replace("{severity}", &ctx.severity)
            .replace("{asset_type}", &ctx.asset_type)
            .replace("{anomaly_reasons}", &anomaly_text);

        // Generate rule-based 1-2-3 step recommendations
        let mut recommended_actions = Vec::new();
        let mut action_text_lines = Vec::new();

        for (idx, (title, pattern)) in template.action_steps.iter().enumerate() {
            let step_num = (idx + 1) as u8;
            let inst = pattern
                .replace("{src_ip}", &ctx.src_ip)
                .replace("{dst_host}", &dst_display)
                .replace("{protocol}", &ctx.protocol);

            action_text_lines.push(format!("{}. {}", step_num, inst));
            recommended_actions.push(ActionRecommendation {
                step_number: step_num,
                title: title.clone(),
                instruction: inst,
            });
        }

        let formatted_actions_text = format!("Aksiyon: {}", action_text_lines.join(", "));

        let formatted_full_block = format!(
            "🧠 Neden önemli?\n\n{}\n\n{}",
            paragraph, formatted_actions_text
        );

        WhyThisMattersEvaluation {
            why_this_matters_paragraph: paragraph,
            recommended_actions,
            formatted_actions_text,
            formatted_full_block,
        }
    }
}

/// Global thread-safe WhyThisMattersEngine singleton.
pub fn global_why_this_matters_engine() -> &'static std::sync::Mutex<WhyThisMattersEngine> {
    static ENGINE: std::sync::OnceLock<std::sync::Mutex<WhyThisMattersEngine>> =
        std::sync::OnceLock::new();
    ENGINE.get_or_init(|| std::sync::Mutex::new(WhyThisMattersEngine::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_why_this_matters_smb_template() {
        let engine = WhyThisMattersEngine::new();
        let ctx = TemplateContext {
            src_ip: "10.0.1.47".to_string(),
            dst_ip: "10.0.5.18".to_string(),
            dst_host: "FIN-DB-01".to_string(),
            department: "HR".to_string(),
            protocol: "SMB".to_string(),
            severity: "HIGH".to_string(),
            anomaly_reasons:
                "Bu erişim mesai dışı saatte, normalin 39 katı bağlantı ile gerçekleşti."
                    .to_string(),
            asset_type: "Production Database".to_string(),
        };

        let eval = engine.evaluate(&ctx);
        assert!(eval.why_this_matters_paragraph.contains("FIN-DB-01"));
        assert!(eval.why_this_matters_paragraph.contains("HR"));
        assert!(eval
            .formatted_actions_text
            .contains("1. Bu host'u (10.0.1.47) hemen izole edin."));
        assert!(eval.formatted_full_block.contains("🧠 Neden önemli?"));
    }

    #[test]
    fn test_why_this_matters_rdp_template() {
        let engine = WhyThisMattersEngine::new();
        let ctx = TemplateContext {
            src_ip: "192.168.1.100".to_string(),
            dst_ip: "10.0.0.5".to_string(),
            dst_host: "SRV-ADMIN".to_string(),
            department: "IT".to_string(),
            protocol: "RDP".to_string(),
            severity: "CRITICAL".to_string(),
            anomaly_reasons: "".to_string(),
            asset_type: "Server".to_string(),
        };

        let eval = engine.evaluate(&ctx);
        assert!(eval
            .why_this_matters_paragraph
            .contains("Remote Desktop Protocol"));
        assert_eq!(eval.recommended_actions.len(), 3);
    }
}
