// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

//! Enterprise Multi-Tenancy & SaaS Isolation Engine (§8.3).
//!
//! Provides:
//! - Tenant isolation & scope validation (§8.3.1)
//! - Custom branding (logo, colors, email template) per tenant (§8.3.2)
//! - Usage metering & quota enforcement (events/sec, sensors, storage) (§8.3.3)
//! - Isolated single-tenant backup export & restore importer (§8.3.4)

use std::collections::HashMap;

/// Tenant Isolation Context (§8.3.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct TenantContext {
    pub tenant_id: String,
    pub tenant_name: String,
}

impl TenantContext {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            tenant_id: id.into(),
            tenant_name: name.into(),
        }
    }

    pub fn validate_access(&self, resource_tenant_id: &str) -> bool {
        self.tenant_id == resource_tenant_id
    }
}

/// Custom Branding per Tenant (§8.3.2).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CustomBranding {
    pub logo_url: Option<String>,
    pub primary_color_hex: String,   // Default #1E88E5
    pub secondary_color_hex: String, // Default #0D47A1
    pub email_template_html: String,
}

impl Default for CustomBranding {
    fn default() -> Self {
        Self {
            logo_url: None,
            primary_color_hex: "#1E88E5".to_string(),
            secondary_color_hex: "#0D47A1".to_string(),
            email_template_html: "<div><h2>{{subject}}</h2><p>{{body}}</p></div>".to_string(),
        }
    }
}

/// Tenant Usage Quota & Metering (§8.3.3).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TenantQuota {
    pub max_events_per_sec: u64,
    pub max_sensors: usize,
    pub max_storage_bytes: u64,
}

impl Default for TenantQuota {
    fn default() -> Self {
        Self {
            max_events_per_sec: 10_000,
            max_sensors: 50,
            max_storage_bytes: 1_000_000_000_000, // 1 TB
        }
    }
}

/// Usage Tracker for Tenant (§8.3.3).
#[derive(Debug, Default)]
pub struct UsageMeter {
    pub current_events_per_sec: u64,
    pub active_sensors: usize,
    pub used_storage_bytes: u64,
}

impl UsageMeter {
    pub fn is_over_quota(&self, quota: &TenantQuota) -> bool {
        self.current_events_per_sec > quota.max_events_per_sec
            || self.active_sensors > quota.max_sensors
            || self.used_storage_bytes > quota.max_storage_bytes
    }
}

/// Single Tenant Backup & Restore Package (§8.3.4).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TenantBackupPackage {
    pub tenant_id: String,
    pub branding: CustomBranding,
    pub quota: TenantQuota,
    pub alerts_json: Vec<String>,
    pub timestamp: String,
}

/// Multi-Tenancy Manager Engine (§8.3).
#[derive(Debug, Default)]
pub struct MultiTenancyEngine {
    pub brandings: HashMap<String, CustomBranding>,
    pub quotas: HashMap<String, TenantQuota>,
    pub meters: HashMap<String, UsageMeter>,
}

impl MultiTenancyEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_branding(&mut self, tenant_id: &str, branding: CustomBranding) {
        self.brandings.insert(tenant_id.to_string(), branding);
    }

    pub fn export_tenant_backup(&self, tenant_id: &str) -> TenantBackupPackage {
        TenantBackupPackage {
            tenant_id: tenant_id.to_string(),
            branding: self.brandings.get(tenant_id).cloned().unwrap_or_default(),
            quota: self.quotas.get(tenant_id).cloned().unwrap_or_default(),
            alerts_json: vec![],
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn import_tenant_backup(&mut self, package: TenantBackupPackage) {
        self.brandings
            .insert(package.tenant_id.clone(), package.branding);
        self.quotas.insert(package.tenant_id.clone(), package.quota);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_isolation() {
        let tenant1 = TenantContext::new("t1", "Company A");
        assert!(tenant1.validate_access("t1"));
        assert!(!tenant1.validate_access("t2"));
    }

    #[test]
    fn test_custom_branding_and_quota() {
        let mut engine = MultiTenancyEngine::new();
        let mut b = CustomBranding::default();
        b.primary_color_hex = "#FF0000".to_string();
        engine.set_branding("tenant_x", b.clone());

        assert_eq!(
            engine.brandings.get("tenant_x").unwrap().primary_color_hex,
            "#FF0000"
        );

        let meter = UsageMeter {
            current_events_per_sec: 15_000,
            active_sensors: 10,
            used_storage_bytes: 500_000,
        };
        assert!(meter.is_over_quota(&TenantQuota::default()));
    }

    #[test]
    fn test_tenant_backup_and_restore() {
        let mut engine = MultiTenancyEngine::new();
        let mut b = CustomBranding::default();
        b.primary_color_hex = "#00FF00".to_string();
        engine.set_branding("tenant_y", b);

        let backup = engine.export_tenant_backup("tenant_y");
        assert_eq!(backup.tenant_id, "tenant_y");

        let mut engine2 = MultiTenancyEngine::new();
        engine2.import_tenant_backup(backup);
        assert_eq!(
            engine2.brandings.get("tenant_y").unwrap().primary_color_hex,
            "#00FF00"
        );
    }
}
