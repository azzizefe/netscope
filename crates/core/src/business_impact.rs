// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

//! 100% Offline Deterministic Asset Inventory & Business Impact Engine (§1.1.6).
//!
//! Provides zero-token asset inventory management (CMDB sync API), asset criticality tiering (Tier 1-4),
//! compliance framework resolution (PCI-DSS, KVKK, GDPR, ISO 27001, HIPAA), and business impact estimation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};

/// Asset Criticality Level (Tier 1 - Tier 4) (§1.1.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AssetCriticality {
    Tier1Critical,
    Tier2High,
    Tier3Medium,
    Tier4Low,
}

impl AssetCriticality {
    pub fn as_str(&self) -> &'static str {
        match self {
            AssetCriticality::Tier1Critical => "CRITICAL",
            AssetCriticality::Tier2High => "HIGH",
            AssetCriticality::Tier3Medium => "MEDIUM",
            AssetCriticality::Tier4Low => "LOW",
        }
    }

    pub fn tier_name(&self) -> &'static str {
        match self {
            AssetCriticality::Tier1Critical => "Tier 1 - Critical Infrastructure",
            AssetCriticality::Tier2High => "Tier 2 - Important Systems",
            AssetCriticality::Tier3Medium => "Tier 3 - Standard Internal Assets",
            AssetCriticality::Tier4Low => "Tier 4 - Non-essential Assets",
        }
    }
}

/// Data Classification Level (§1.1.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataClassification {
    Confidential,
    Restricted,
    Internal,
    Public,
}

impl DataClassification {
    pub fn as_str(&self) -> &'static str {
        match self {
            DataClassification::Confidential => "CONFIDENTIAL",
            DataClassification::Restricted => "RESTRICTED",
            DataClassification::Internal => "INTERNAL",
            DataClassification::Public => "PUBLIC",
        }
    }
}

/// Estimated Financial/Maddi Impact Level (§1.1.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinancialImpactLevel {
    Critical,
    High,
    Medium,
    Low,
}

impl FinancialImpactLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            FinancialImpactLevel::Critical => "KRİTİK (ağır regülasyon cezası + hizmet kesintisi)",
            FinancialImpactLevel::High => "YÜKSEK (regülasyon cezası + itibar kaybı)",
            FinancialImpactLevel::Medium => "ORTA (sınırlı operational etki)",
            FinancialImpactLevel::Low => "DÜŞÜK (önemsiz etki)",
        }
    }
}

/// Asset Item in CMDB / Inventory (§1.1.6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetItem {
    pub id: String,
    pub hostname: String,
    pub ip_address: IpAddr,
    pub mac_address: Option<String>,
    pub asset_type: String,
    pub department: String,
    pub criticality: AssetCriticality,
    pub data_classification: DataClassification,
    pub compliance_frameworks: Vec<String>,
    pub owner: Option<String>,
    pub description: Option<String>,
}

/// Business Impact Evaluation report (§1.1.6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessImpactEvaluation {
    pub affected_asset_name: String,
    pub ip_address: String,
    pub criticality_label: String,
    pub data_classification: String,
    pub compliance_frameworks: Vec<String>,
    pub business_impact_description: String,
    pub estimated_financial_impact: String,
    pub formatted_summary: String,
}

/// Asset Inventory Registry / Manager (CMDB Sync API) (§1.1.6).
#[derive(Debug, Clone, Default)]
pub struct AssetInventoryRegistry {
    pub assets_by_ip: HashMap<IpAddr, AssetItem>,
    pub assets_by_hostname: HashMap<String, AssetItem>,
}

impl AssetInventoryRegistry {
    pub fn new() -> Self {
        let mut reg = Self::default();
        // Seed default demo asset (FIN-DB-01) for tests and initial setup
        let default_ip: IpAddr = "10.0.5.18".parse().unwrap();
        let fin_db = AssetItem {
            id: "asset-fin-db-01".to_string(),
            hostname: "FIN-DB-01".to_string(),
            ip_address: default_ip,
            mac_address: Some("00:15:5D:1A:2B:3C".to_string()),
            asset_type: "Production Database".to_string(),
            department: "Finance".to_string(),
            criticality: AssetCriticality::Tier1Critical,
            data_classification: DataClassification::Confidential,
            compliance_frameworks: vec![
                "PCI-DSS (kredi kartı verisi)".to_string(),
                "KVKK (çalışan maaş bilgisi)".to_string(),
            ],
            owner: Some("Finance SecOps".to_string()),
            description: Some("Main core production database for finance & payroll".to_string()),
        };
        reg.register_asset(fin_db);
        reg
    }

    /// Register or update an asset in CMDB inventory (CMDB Sync API).
    pub fn register_asset(&mut self, asset: AssetItem) {
        self.assets_by_ip.insert(asset.ip_address, asset.clone());
        self.assets_by_hostname.insert(asset.hostname.to_lowercase(), asset);
    }

    /// Get asset by IP address.
    pub fn get_by_ip(&self, ip: IpAddr) -> Option<&AssetItem> {
        self.assets_by_ip.get(&ip)
    }

    /// Get asset by Hostname.
    pub fn get_by_hostname(&self, hostname: &str) -> Option<&AssetItem> {
        self.assets_by_hostname.get(&hostname.to_lowercase())
    }

    /// List all assets in inventory.
    pub fn list_assets(&self) -> Vec<AssetItem> {
        self.assets_by_ip.values().cloned().collect()
    }

    /// Remove asset by IP.
    pub fn remove_asset(&mut self, ip: IpAddr) -> Option<AssetItem> {
        if let Some(asset) = self.assets_by_ip.remove(&ip) {
            self.assets_by_hostname.remove(&asset.hostname.to_lowercase());
            Some(asset)
        } else {
            None
        }
    }

    /// Evaluate business impact for a target host/IP (§1.1.6).
    pub fn evaluate_impact(&self, target_ip: Option<IpAddr>, target_host: Option<&str>) -> BusinessImpactEvaluation {
        let asset_opt = target_ip
            .and_then(|ip| self.get_by_ip(ip))
            .or_else(|| target_host.and_then(|h| self.get_by_hostname(h)));

        if let Some(asset) = asset_opt {
            let criticality_label = format!(
                "{} ({}, {})",
                asset.criticality.as_str(),
                asset.asset_type,
                asset.department
            );

            let impact_desc = match asset.criticality {
                AssetCriticality::Tier1Critical => format!(
                    "Bu sunucuya yetkisiz erişim, tüm {} verilerinin sızmasına ve {} ihlaline yol açabilir.",
                    asset.department.to_lowercase(),
                    asset.compliance_frameworks.first().cloned().unwrap_or_else(|| "regülasyon".to_string())
                ),
                AssetCriticality::Tier2High => format!(
                    "Bu sistemin ({}) ele geçirilmesi, {} departmanı operasyonlarında ciddi aksamalara yol açabilir.",
                    asset.hostname, asset.department
                ),
                AssetCriticality::Tier3Medium => format!(
                    "Bu varlıktaki ({}) ihlal, yerel erişim riskine ve internal veri sızıntısına neden olabilir.",
                    asset.hostname
                ),
                AssetCriticality::Tier4Low => format!(
                    "Bu cihazdaki ({}) aktivite düşük öncelikli olup iş sürekliliğini doğrudan tehdit etmez.",
                    asset.hostname
                ),
            };

            let fin_level = match asset.criticality {
                AssetCriticality::Tier1Critical => FinancialImpactLevel::High,
                AssetCriticality::Tier2High => FinancialImpactLevel::High,
                AssetCriticality::Tier3Medium => FinancialImpactLevel::Medium,
                AssetCriticality::Tier4Low => FinancialImpactLevel::Low,
            };

            let formatted_summary = format!(
                "Etkilenen varlık: {}\n  Kritiklik: {}\n  Veri sınıflandırması: {}\n  Compliance: {}\n  İş etkisi: {}\n  Tahmini maddi etki: {}",
                asset.hostname,
                criticality_label,
                asset.data_classification.as_str(),
                asset.compliance_frameworks.join(", "),
                impact_desc,
                fin_level.as_str()
            );

            BusinessImpactEvaluation {
                affected_asset_name: asset.hostname.clone(),
                ip_address: asset.ip_address.to_string(),
                criticality_label,
                data_classification: asset.data_classification.as_str().to_string(),
                compliance_frameworks: asset.compliance_frameworks.clone(),
                business_impact_description: impact_desc,
                estimated_financial_impact: fin_level.as_str().to_string(),
                formatted_summary,
            }
        } else {
            let name = target_host
                .map(|h| h.to_string())
                .or_else(|| target_ip.map(|ip| ip.to_string()))
                .unwrap_or_else(|| "Unknown-Host".to_string());

            let formatted_summary = format!(
                "Etkilenen varlık: {}\n  Kritiklik: UNKNOWN (Envanterde Tanımsız Host)\n  Veri sınıflandırması: INTERNAL\n  Compliance: Standart Güvenlik Politikası\n  İş etkisi: Tanımsız varlık erişimi, potansiyel yetkisiz erişim riski oluşturur.\n  Tahmini maddi etki: ORTA (bilinmeyen varlık tespiti gereklidir)",
                name
            );

            BusinessImpactEvaluation {
                affected_asset_name: name.clone(),
                ip_address: target_ip.map(|ip| ip.to_string()).unwrap_or_default(),
                criticality_label: "UNKNOWN".to_string(),
                data_classification: "INTERNAL".to_string(),
                compliance_frameworks: vec!["Standart Güvenlik Politikası".to_string()],
                business_impact_description: "Tanımsız varlık erişimi, potansiyel yetkisiz erişim riski oluşturur.".to_string(),
                estimated_financial_impact: FinancialImpactLevel::Medium.as_str().to_string(),
                formatted_summary,
            }
        }
    }
}

/// Global thread-safe Asset Inventory Registry singleton.
pub fn global_asset_registry() -> &'static Mutex<AssetInventoryRegistry> {
    static REG: OnceLock<Mutex<AssetInventoryRegistry>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(AssetInventoryRegistry::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asset_inventory_registration_and_impact() {
        let reg = AssetInventoryRegistry::new();
        let ip: IpAddr = "10.0.5.18".parse().unwrap();
        let asset = reg.get_by_ip(ip).unwrap();
        assert_eq!(asset.hostname, "FIN-DB-01");
        assert_eq!(asset.criticality, AssetCriticality::Tier1Critical);

        let impact = reg.evaluate_impact(Some(ip), Some("FIN-DB-01"));
        assert_eq!(impact.affected_asset_name, "FIN-DB-01");
        assert!(impact.formatted_summary.contains("CRITICAL (Production Database, Finance)"));
        assert!(impact.formatted_summary.contains("CONFIDENTIAL"));
        assert!(impact.formatted_summary.contains("PCI-DSS"));
    }

    #[test]
    fn test_custom_asset_registration() {
        let mut reg = AssetInventoryRegistry::new();
        let ip: IpAddr = "192.168.10.50".parse().unwrap();
        let new_asset = AssetItem {
            id: "asset-dc-01".to_string(),
            hostname: "DC-01".to_string(),
            ip_address: ip,
            mac_address: None,
            asset_type: "Domain Controller".to_string(),
            department: "IT Infrastructure".to_string(),
            criticality: AssetCriticality::Tier1Critical,
            data_classification: DataClassification::Restricted,
            compliance_frameworks: vec!["ISO 27001".to_string()],
            owner: Some("IT SysAdmin".to_string()),
            description: Some("Primary Active Directory Domain Controller".to_string()),
        };
        reg.register_asset(new_asset);

        let retrieved = reg.get_by_ip(ip).unwrap();
        assert_eq!(retrieved.hostname, "DC-01");
    }
}
