// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

//! Granular RBAC, Enterprise IAM (SSO OIDC / SAML 2.0) & Tiered Access Control (§3.1, §3.2).
//!
//! Provides:
//! - §3.1 SSO & Enterprise Identity Provider (Azure AD, Okta, Keycloak OIDC/SAML2 token & claim mapping)
//! - §3.2 Enterprise Tiered RBAC Enforcement (Tier 1 Analyst payload masking, Tier 2/3 Incident Responder, Auditor, Admin)
//! - 50+ Granular Permission string definitions covering all Netscope domains
//! - Dynamic Custom Role Builder Engine

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// SSO Authentication Protocols (§3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SsoProtocol {
    OpenIdConnectOidc,
    Saml2,
    OAuth2,
}

/// Supported SSO Enterprise Providers (§3.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SsoProviderType {
    AzureActiveDirectory,
    Okta,
    Keycloak,
    GenericOidc,
}

/// SSO Identity Provider Configuration (§3.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoProviderConfig {
    pub provider_id: String,
    pub name: String,
    pub provider_type: SsoProviderType,
    pub protocol: SsoProtocol,
    pub client_id: String,
    pub issuer_url: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub enabled: bool,
    pub role_claim_mapping: HashMap<String, String>, // e.g. "AzureAD_SOC_Tier1" -> "tier1_analyst"
}

/// Claims extracted from OIDC JWT / SAML Assertion (§3.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoUserClaims {
    pub user_id: String,
    pub email: String,
    pub full_name: String,
    pub groups: Vec<String>,
    pub provider: String,
}

/// Active SSO Authenticated User Session (§3.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoUserSession {
    pub session_token: String,
    pub user_claims: SsoUserClaims,
    pub assigned_role: String,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Comprehensive 50+ Granular Permissions List (§3.2).
pub const ALL_PERMISSIONS: &[&str] = &[
    // PCAP & Traffic Analysis
    "pcap:read",
    "pcap:export",
    "pcap:payload_raw", // Explicit permission for unmasked payload
    "pcap:delete",
    "pcap:reorder",
    "pcap:replay",
    // Firewall & Mitigation
    "firewall:block",
    "firewall:unblock",
    "firewall:manage",
    // Alerts & Incidents
    "alert:read",
    "alert:write",
    "alert:ack",
    "alert:delete",
    "alert:assign",
    "incident:create",
    "incident:update",
    // Detection Rules & Threat Hunting
    "rules:read",
    "rules:write",
    "rules:delete",
    "rules:enable",
    "hunt:execute",
    "sigma:import",
    "stix:export",
    // Fleet & Sensor Operations
    "sensor:read",
    "sensor:write",
    "sensor:command",
    "sensor:delete",
    "sensor:restart",
    "sensor:upgrade",
    // Reports & Dashboards & Compliance
    "report:read",
    "report:create",
    "report:schedule",
    "report:export",
    "compliance:read",
    "dashboard:read",
    "dashboard:customize",
    // SIEM & Connectors
    "siem:matrix",
    "siem:export",
    "siem:connector_write",
    "siem:metrics",
    // User Management & Security Administration
    "user:read",
    "user:write",
    "user:delete",
    "user:unlock",
    "role:read",
    "role:write",
    "role:delete",
    "session:read",
    "session:revoke",
    "apikey:create",
    "apikey:revoke",
    // Audit & Forensics
    "audit:read",
    "audit:verify",
    "forensics:timeline",
    "forensics:extract",
    // SOAR & Automations
    "soar:read",
    "soar:execute",
    "soar:write",
    "webhook:manage",
];

/// Representation of a Role with assigned permissions (§3.2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoleDefinition {
    pub name: String,
    pub description: String,
    pub permissions: HashSet<String>,
    pub is_builtin: bool,
    pub can_view_raw_payload: bool, // §3.2 Tier 1 restriction toggle
}

#[derive(Debug, Clone)]
pub struct RbacEngine {
    inner: Arc<RwLock<RbacStore>>,
}

#[derive(Debug)]
struct RbacStore {
    roles: HashMap<String, RoleDefinition>,
    sso_providers: HashMap<String, SsoProviderConfig>,
}

impl Default for RbacEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RbacEngine {
    pub fn new() -> Self {
        let mut store = RbacStore {
            roles: HashMap::new(),
            sso_providers: HashMap::new(),
        };

        // Initialize Default SSO Provider (Azure AD) (§3.1)
        let mut azure_mapping = HashMap::new();
        azure_mapping.insert("SG-Netscope-Tier1".to_string(), "tier1_analyst".to_string());
        azure_mapping.insert(
            "SG-Netscope-Tier23".to_string(),
            "tier2_3_responder".to_string(),
        );
        azure_mapping.insert("SG-Netscope-Auditors".to_string(), "auditor".to_string());
        azure_mapping.insert("SG-Netscope-Admins".to_string(), "admin".to_string());

        let azure_provider = SsoProviderConfig {
            provider_id: "sso_azure_ad".to_string(),
            name: "Enterprise Azure Active Directory (Entra ID)".to_string(),
            provider_type: SsoProviderType::AzureActiveDirectory,
            protocol: SsoProtocol::OpenIdConnectOidc,
            client_id: "netscope-app-client-id".to_string(),
            issuer_url: "https://login.microsoftonline.com/corp-tenant-id/v2.0".to_string(),
            authorization_endpoint:
                "https://login.microsoftonline.com/corp-tenant-id/oauth2/v2.0/authorize".to_string(),
            token_endpoint: "https://login.microsoftonline.com/corp-tenant-id/oauth2/v2.0/token"
                .to_string(),
            userinfo_endpoint: "https://graph.microsoft.com/oidc/userinfo".to_string(),
            enabled: true,
            role_claim_mapping: azure_mapping,
        };
        store
            .sso_providers
            .insert(azure_provider.provider_id.clone(), azure_provider);

        // Initialize Pre-defined Enterprise Roles (§3.2)
        // 1. Admin — Full system access & config control
        let admin_perms: HashSet<String> = ALL_PERMISSIONS.iter().map(|s| s.to_string()).collect();
        store.roles.insert(
            "admin".to_string(),
            RoleDefinition {
                name: "admin".to_string(),
                description: "System Administrator with unrestricted access across all modules"
                    .to_string(),
                permissions: admin_perms,
                is_builtin: true,
                can_view_raw_payload: true,
            },
        );

        // 2. Tier 1 Analyst — Alerts only, payload is masked, cannot block IPs or download raw PCAP
        let tier1_perms: HashSet<String> = vec![
            "alert:read",
            "alert:ack",
            "dashboard:read",
            "report:read",
            "siem:metrics",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        store.roles.insert(
            "tier1_analyst".to_string(),
            RoleDefinition {
                name: "tier1_analyst".to_string(),
                description: "Tier 1 SOC Analyst: Can view alerts & dashboards; raw payload is masked for privacy".to_string(),
                permissions: tier1_perms,
                is_builtin: true,
                can_view_raw_payload: false, // Payload strictly masked!
            },
        );

        // 3. Tier 2/3 Incident Responder — Full triage, raw PCAP download, IP firewall blocking & SOAR execution
        let tier2_perms: HashSet<String> = vec![
            "pcap:read",
            "pcap:export",
            "pcap:payload_raw",
            "firewall:block",
            "firewall:unblock",
            "alert:read",
            "alert:write",
            "alert:ack",
            "alert:assign",
            "incident:create",
            "incident:update",
            "rules:read",
            "rules:write",
            "hunt:execute",
            "report:read",
            "report:create",
            "dashboard:read",
            "forensics:timeline",
            "forensics:extract",
            "soar:read",
            "soar:execute",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        store.roles.insert(
            "tier2_3_responder".to_string(),
            RoleDefinition {
                name: "tier2_3_responder".to_string(),
                description: "Tier 2/3 Incident Responder: Can inspect raw PCAP, block IPs, and execute SOAR playbooks".to_string(),
                permissions: tier2_perms,
                is_builtin: true,
                can_view_raw_payload: true,
            },
        );

        // 4. Auditor / Compliance Officer — Read-only compliance & audit trails
        let auditor_perms: HashSet<String> = vec![
            "report:read",
            "report:export",
            "compliance:read",
            "audit:read",
            "audit:verify",
            "dashboard:read",
            "siem:metrics",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        store.roles.insert(
            "auditor".to_string(),
            RoleDefinition {
                name: "auditor".to_string(),
                description: "Auditor / Compliance Officer: Read-only compliance reports (KVKK/GDPR/ISO 27001) & audit logs".to_string(),
                permissions: auditor_perms,
                is_builtin: true,
                can_view_raw_payload: false,
            },
        );

        Self {
            inner: Arc::new(RwLock::new(store)),
        }
    }

    /// SSO Claim-to-Role Mapping Engine (§3.1).
    pub fn map_sso_claims_to_role(&self, provider_id: &str, claims: &SsoUserClaims) -> String {
        let store = self.inner.read();
        if let Some(provider) = store.sso_providers.get(provider_id) {
            for group in &claims.groups {
                if let Some(mapped_role) = provider.role_claim_mapping.get(group) {
                    return mapped_role.clone();
                }
            }
        }
        // Fallback default role
        "tier1_analyst".to_string()
    }

    /// Check if a role is permitted to view raw unmasked packet payload (§3.2).
    pub fn can_view_raw_payload(&self, role_name: &str) -> bool {
        let store = self.inner.read();
        if let Some(role) = store.roles.get(&role_name.to_lowercase()) {
            role.can_view_raw_payload
        } else {
            false
        }
    }

    /// Check if a role has a specific permission.
    pub fn role_has_permission(&self, role_name: &str, required_permission: &str) -> bool {
        let store = self.inner.read();
        if let Some(role) = store.roles.get(&role_name.to_lowercase()) {
            role.permissions.contains("*") || role.permissions.contains(required_permission)
        } else {
            false
        }
    }

    /// Custom Role Builder: Create or Update a custom role (§3.2).
    pub fn create_custom_role(
        &self,
        name: &str,
        description: &str,
        permissions: Vec<String>,
        can_view_raw_payload: bool,
    ) -> Result<RoleDefinition, String> {
        let name_lower = name.trim().to_lowercase();
        if name_lower.is_empty() {
            return Err("Role name cannot be empty".to_string());
        }

        let mut store = self.inner.write();
        if let Some(existing) = store.roles.get(&name_lower) {
            if existing.is_builtin {
                return Err(format!("Built-in role '{name}' cannot be modified"));
            }
        }

        let perm_set: HashSet<String> = permissions.into_iter().collect();
        let role_def = RoleDefinition {
            name: name_lower.clone(),
            description: description.to_string(),
            permissions: perm_set,
            is_builtin: false,
            can_view_raw_payload,
        };

        store.roles.insert(name_lower, role_def.clone());
        Ok(role_def)
    }

    /// Delete custom role.
    pub fn delete_custom_role(&self, name: &str) -> Result<bool, String> {
        let name_lower = name.trim().to_lowercase();
        let mut store = self.inner.write();

        if let Some(role) = store.roles.get(&name_lower) {
            if role.is_builtin {
                return Err(format!("Built-in role '{name}' cannot be deleted"));
            }
        } else {
            return Ok(false);
        }

        Ok(store.roles.remove(&name_lower).is_some())
    }

    /// Get details of a specific role.
    pub fn get_role(&self, name: &str) -> Option<RoleDefinition> {
        let store = self.inner.read();
        store.roles.get(&name.to_lowercase()).cloned()
    }

    /// List all defined roles (§3.2).
    pub fn list_roles(&self) -> Vec<RoleDefinition> {
        let store = self.inner.read();
        let mut roles: Vec<_> = store.roles.values().cloned().collect();
        roles.sort_by(|a, b| a.name.cmp(&b.name));
        roles
    }

    /// Get list of all available permission strings.
    pub fn get_all_permissions(&self) -> Vec<&'static str> {
        ALL_PERMISSIONS.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sso_claims_mapping() {
        let rbac = RbacEngine::new();

        let claims = SsoUserClaims {
            user_id: "usr-12345".to_string(),
            email: "analyst@corp.local".to_string(),
            full_name: "John Doe".to_string(),
            groups: vec!["SG-Netscope-Tier23".to_string()],
            provider: "AzureAD".to_string(),
        };

        let role = rbac.map_sso_claims_to_role("sso_azure_ad", &claims);
        assert_eq!(role, "tier2_3_responder");
    }

    #[test]
    fn test_tiered_rbac_permissions_and_payload_masking() {
        let rbac = RbacEngine::new();

        // Tier 1 Analyst: Payload MUST be masked, cannot block IP
        assert!(rbac.role_has_permission("tier1_analyst", "alert:read"));
        assert!(!rbac.role_has_permission("tier1_analyst", "firewall:block"));
        assert!(!rbac.can_view_raw_payload("tier1_analyst"));

        // Tier 2/3 Responder: Raw payload visible, can block IP
        assert!(rbac.role_has_permission("tier2_3_responder", "alert:read"));
        assert!(rbac.role_has_permission("tier2_3_responder", "firewall:block"));
        assert!(rbac.can_view_raw_payload("tier2_3_responder"));

        // Auditor: Compliance read only
        assert!(rbac.role_has_permission("auditor", "compliance:read"));
        assert!(!rbac.role_has_permission("auditor", "firewall:block"));
        assert!(!rbac.can_view_raw_payload("auditor"));

        // Admin: All privileges
        assert!(rbac.role_has_permission("admin", "firewall:block"));
        assert!(rbac.role_has_permission("admin", "user:delete"));
        assert!(rbac.can_view_raw_payload("admin"));
    }

    #[test]
    fn test_custom_role_creation() {
        let rbac = RbacEngine::new();

        let custom = rbac
            .create_custom_role(
                "soar_bot",
                "Automated SOAR service account",
                vec!["firewall:block".into(), "soar:execute".into()],
                false,
            )
            .unwrap();

        assert_eq!(custom.name, "soar_bot");
        assert!(rbac.role_has_permission("soar_bot", "firewall:block"));
        assert!(!rbac.can_view_raw_payload("soar_bot"));
    }
}
