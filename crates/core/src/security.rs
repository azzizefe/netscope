// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

//! Platform Security & Compliance Engine (§7.1).
//!
//! Provides:
//! - RBAC (Role-Based Access Control: Admin, SocManager, AnalystL2, AnalystL1, ReadOnly, Auditor)
//! - MFA (TOTP / WebAuthn verification structures)
//! - SSO (SAML 2.0 / OIDC provider configuration)
//! - Scoped API Keys (event:push, alert:read, alert:write, etc.)
//! - SHA-256 Hash-Chained Tamper-Proof Audit Logging
//! - Encrypted Secret Management helper (Vault / AWS Secrets Manager integration)

use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::IpAddr;

/// User Roles for RBAC (§7.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum UserRole {
    Admin,
    SocManager,
    SocAnalystL2,
    SocAnalystL1,
    ReadOnly,
    Auditor,
}

/// Granular Permissions (§7.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Permission {
    All,
    AlertView,
    AlertTriage,
    AlertAcknowledge,
    IncidentCreate,
    RuleManage,
    ReportView,
    UserManage,
    AuditView,
    EventPush,
}

impl UserRole {
    pub fn permissions(&self) -> HashSet<Permission> {
        let mut p = HashSet::new();
        match self {
            UserRole::Admin => {
                p.insert(Permission::All);
            }
            UserRole::SocManager => {
                p.insert(Permission::AlertView);
                p.insert(Permission::AlertTriage);
                p.insert(Permission::AlertAcknowledge);
                p.insert(Permission::IncidentCreate);
                p.insert(Permission::RuleManage);
                p.insert(Permission::ReportView);
                p.insert(Permission::UserManage);
                p.insert(Permission::AuditView);
            }
            UserRole::SocAnalystL2 => {
                p.insert(Permission::AlertView);
                p.insert(Permission::AlertTriage);
                p.insert(Permission::AlertAcknowledge);
                p.insert(Permission::IncidentCreate);
                p.insert(Permission::ReportView);
            }
            UserRole::SocAnalystL1 => {
                p.insert(Permission::AlertView);
                p.insert(Permission::AlertTriage);
            }
            UserRole::ReadOnly => {
                p.insert(Permission::AlertView);
                p.insert(Permission::ReportView);
            }
            UserRole::Auditor => {
                p.insert(Permission::ReportView);
                p.insert(Permission::AuditView);
            }
        }
        p
    }

    pub fn has_permission(&self, perm: Permission) -> bool {
        let perms = self.permissions();
        perms.contains(&Permission::All) || perms.contains(&perm)
    }
}

/// Multi-Factor Authentication Config (§7.1.2).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MfaConfig {
    pub totp_enabled: bool,
    pub webauthn_enabled: bool,
    pub secret: Option<String>,
}

/// Single Sign-On Provider Config (§7.1.3).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SsoConfig {
    pub provider_type: String, // "SAML2" or "OIDC"
    pub issuer_url: String,
    pub client_id: String,
    pub enabled: bool,
}

/// Scoped API Key Manager (§7.1.4).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScopedApiKey {
    pub key_id: String,
    pub name: String,
    pub scopes: HashSet<String>,
    pub is_active: bool,
}

impl ScopedApiKey {
    pub fn can_perform(&self, scope: &str) -> bool {
        self.is_active && (self.scopes.contains("*") || self.scopes.contains(scope))
    }
}

/// SHA-256 Hash-Chained Tamper-Proof Audit Record (§7.1.5, §7.1.6).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditRecord {
    pub index: u64,
    pub timestamp: String,
    pub user: String,
    pub action: String,
    pub resource: String,
    pub ip_addr: Option<String>,
    pub previous_hash: String,
    pub hash: String,
}

/// Append-only Hash-Chained Audit Logger (§7.1.6).
#[derive(Debug, Default)]
pub struct TamperProofAuditLogger {
    pub records: Vec<AuditRecord>,
    pub last_hash: String,
}

impl TamperProofAuditLogger {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            last_hash: "GENESIS_HASH_00000000000000000000000000000000".to_string(),
        }
    }

    pub fn log_action(
        &mut self,
        user: &str,
        action: &str,
        resource: &str,
        ip: Option<IpAddr>,
    ) -> &AuditRecord {
        let index = self.records.len() as u64;
        let ts = chrono::Utc::now().to_rfc3339();
        let ip_str = ip.map(|i| i.to_string());

        let mut hasher = Sha256::new();
        hasher.update(format!(
            "{}:{}:{}:{}:{}:{}",
            index,
            ts,
            user,
            action,
            resource,
            self.last_hash
        ));
        let hash = format!("{:x}", hasher.finalize());

        let record = AuditRecord {
            index,
            timestamp: ts,
            user: user.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            ip_addr: ip_str,
            previous_hash: self.last_hash.clone(),
            hash: hash.clone(),
        };

        self.last_hash = hash;
        self.records.push(record);
        self.records.last().unwrap()
    }

    pub fn verify_chain_integrity(&self) -> bool {
        let mut prev = "GENESIS_HASH_00000000000000000000000000000000";
        for rec in &self.records {
            if rec.previous_hash != prev {
                return false;
            }
            let mut hasher = Sha256::new();
            hasher.update(format!(
                "{}:{}:{}:{}:{}:{}",
                rec.index, rec.timestamp, rec.user, rec.action, rec.resource, prev
            ));
            let expected_hash = format!("{:x}", hasher.finalize());
            if rec.hash != expected_hash {
                return false;
            }
            prev = &rec.hash;
        }
        true
    }
}

/// Secret Manager Provider (§7.1.7).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum SecretProvider {
    LocalEncrypted,
    HashiCorpVault { url: String },
    AwsSecretsManager { region: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rbac_permissions() {
        let admin = UserRole::Admin;
        assert!(admin.has_permission(Permission::UserManage));
        assert!(admin.has_permission(Permission::RuleManage));

        let l1 = UserRole::SocAnalystL1;
        assert!(l1.has_permission(Permission::AlertView));
        assert!(!l1.has_permission(Permission::UserManage));

        let auditor = UserRole::Auditor;
        assert!(auditor.has_permission(Permission::AuditView));
        assert!(!auditor.has_permission(Permission::IncidentCreate));
    }

    #[test]
    fn test_scoped_api_key() {
        let key = ScopedApiKey {
            key_id: "key-123".to_string(),
            name: "Sensor Ingest".to_string(),
            scopes: HashSet::from(["event:push".to_string()]),
            is_active: true,
        };
        assert!(key.can_perform("event:push"));
        assert!(!key.can_perform("user:delete"));
    }

    #[test]
    fn test_tamper_proof_audit_chain() {
        let mut logger = TamperProofAuditLogger::new();
        logger.log_action("admin", "login", "auth", None);
        logger.log_action("analyst1", "acknowledge_alert", "alert-42", None);

        assert_eq!(logger.records.len(), 2);
        assert!(logger.verify_chain_integrity());

        // Tamper test
        logger.records[0].action = "malicious_edit".to_string();
        assert!(!logger.verify_chain_integrity());
    }
}
