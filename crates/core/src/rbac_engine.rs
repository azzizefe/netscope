// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 azzizefe. All rights reserved.

//! Granular RBAC & Custom Role Builder Engine (§2.1.1 - §2.1.3).
//!
//! Provides:
//! - 50+ Granular Permission string definitions covering all netscope domains (§2.1.1)
//! - Pre-defined roles: Admin, Analyst, Auditor, Operator (§2.1.2)
//! - Custom Role Builder: Dynamic role creation, permission assignment, and deletion (§2.1.3)

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Comprehensive 50+ Granular Permissions List (§2.1.1).
pub const ALL_PERMISSIONS: &[&str] = &[
    // PCAP & Traffic Analysis
    "pcap:read",
    "pcap:export",
    "pcap:delete",
    "pcap:reorder",
    "pcap:replay",
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
    // Reports & Dashboards
    "report:read",
    "report:create",
    "report:schedule",
    "report:export",
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

/// Representation of a Role with assigned permissions (§2.1.2, §2.1.3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoleDefinition {
    pub name: String,
    pub description: String,
    pub permissions: HashSet<String>,
    pub is_builtin: bool,
}

#[derive(Debug, Clone)]
pub struct RbacEngine {
    inner: Arc<RwLock<RbacStore>>,
}

#[derive(Debug)]
struct RbacStore {
    roles: HashMap<String, RoleDefinition>,
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
        };

        // Initialize Pre-defined Built-in Roles (§2.1.2)
        // 1. Admin — All permissions
        let admin_perms: HashSet<String> = ALL_PERMISSIONS.iter().map(|s| s.to_string()).collect();
        store.roles.insert(
            "admin".to_string(),
            RoleDefinition {
                name: "admin".to_string(),
                description: "System Administrator with full permissions across all components"
                    .to_string(),
                permissions: admin_perms,
                is_builtin: true,
            },
        );

        // 2. Analyst — Packet inspection, filtering, rule creation, alert triage & acknowledgement
        let analyst_perms: HashSet<String> = vec![
            "pcap:read",
            "pcap:export",
            "pcap:reorder",
            "pcap:replay",
            "alert:read",
            "alert:write",
            "alert:ack",
            "alert:assign",
            "incident:create",
            "incident:update",
            "rules:read",
            "rules:write",
            "rules:enable",
            "hunt:execute",
            "sigma:import",
            "stix:export",
            "report:read",
            "report:create",
            "dashboard:read",
            "siem:matrix",
            "siem:export",
            "forensics:timeline",
            "forensics:extract",
            "soar:read",
            "soar:execute",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        store.roles.insert(
            "analyst".to_string(),
            RoleDefinition {
                name: "analyst".to_string(),
                description: "SOC Analyst with packet inspection, threat hunting, and alert triage capabilities".to_string(),
                permissions: analyst_perms,
                is_builtin: true,
            },
        );

        // 3. Auditor — Read-only reports & audit logs
        let auditor_perms: HashSet<String> = vec![
            "report:read",
            "report:export",
            "audit:read",
            "audit:verify",
            "dashboard:read",
            "siem:matrix",
            "siem:metrics",
            "user:read",
            "role:read",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        store.roles.insert(
            "auditor".to_string(),
            RoleDefinition {
                name: "auditor".to_string(),
                description:
                    "Auditor with read-only access to reports, audit trails, and compliance metrics"
                        .to_string(),
                permissions: auditor_perms,
                is_builtin: true,
            },
        );

        // 4. Operator — Fleet monitoring, start/stop live capture, sensor commands
        let operator_perms: HashSet<String> = vec![
            "sensor:read",
            "sensor:write",
            "sensor:command",
            "sensor:restart",
            "pcap:read",
            "alert:read",
            "dashboard:read",
            "siem:metrics",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        store.roles.insert(
            "operator".to_string(),
            RoleDefinition {
                name: "operator".to_string(),
                description:
                    "Fleet Operator with sensor management and live capture control capabilities"
                        .to_string(),
                permissions: operator_perms,
                is_builtin: true,
            },
        );

        Self {
            inner: Arc::new(RwLock::new(store)),
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

    /// Custom Role Builder: Create or Update a custom role (§2.1.3).
    pub fn create_custom_role(
        &self,
        name: &str,
        description: &str,
        permissions: Vec<String>,
    ) -> Result<RoleDefinition, String> {
        let name_lower = name.trim().to_lowercase();
        if name_lower.is_empty() {
            return Err("Role name cannot be empty".to_string());
        }

        let mut store = self.inner.write();
        if let Some(existing) = store.roles.get(&name_lower) {
            if existing.is_builtin {
                return Err(format!("Built-in role '{}' cannot be modified", name));
            }
        }

        let perm_set: HashSet<String> = permissions.into_iter().collect();
        let role_def = RoleDefinition {
            name: name_lower.clone(),
            description: description.to_string(),
            permissions: perm_set,
            is_builtin: false,
        };

        store.roles.insert(name_lower, role_def.clone());
        Ok(role_def)
    }

    /// Custom Role Builder: Delete a custom role (§2.1.3).
    pub fn delete_custom_role(&self, name: &str) -> Result<bool, String> {
        let name_lower = name.trim().to_lowercase();
        let mut store = self.inner.write();

        if let Some(role) = store.roles.get(&name_lower) {
            if role.is_builtin {
                return Err(format!("Built-in role '{}' cannot be deleted", name));
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

    /// List all defined roles (§2.1.2, §2.1.3).
    pub fn list_roles(&self) -> Vec<RoleDefinition> {
        let store = self.inner.read();
        let mut roles: Vec<_> = store.roles.values().cloned().collect();
        roles.sort_by(|a, b| a.name.cmp(&b.name));
        roles
    }

    /// Get list of all available 50+ granular permission strings (§2.1.1).
    pub fn get_all_permissions(&self) -> Vec<&'static str> {
        ALL_PERMISSIONS.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_roles_and_permissions() {
        let rbac = RbacEngine::new();

        // Admin has all permissions
        assert!(rbac.role_has_permission("admin", "user:delete"));
        assert!(rbac.role_has_permission("admin", "pcap:delete"));

        // Analyst permissions
        assert!(rbac.role_has_permission("analyst", "pcap:read"));
        assert!(rbac.role_has_permission("analyst", "alert:ack"));
        assert!(!rbac.role_has_permission("analyst", "user:delete"));

        // Auditor permissions
        assert!(rbac.role_has_permission("auditor", "audit:read"));
        assert!(rbac.role_has_permission("auditor", "report:export"));
        assert!(!rbac.role_has_permission("auditor", "pcap:delete"));

        // Operator permissions
        assert!(rbac.role_has_permission("operator", "sensor:command"));
        assert!(!rbac.role_has_permission("operator", "user:write"));
    }

    #[test]
    fn test_custom_role_builder() {
        let rbac = RbacEngine::new();

        // Create custom tier-2 SOC role
        let custom = rbac
            .create_custom_role(
                "tier2_hunter",
                "Junior threat hunter role",
                vec![
                    "pcap:read".into(),
                    "hunt:execute".into(),
                    "alert:ack".into(),
                ],
            )
            .unwrap();

        assert_eq!(custom.name, "tier2_hunter");
        assert!(!custom.is_builtin);
        assert!(rbac.role_has_permission("tier2_hunter", "hunt:execute"));
        assert!(!rbac.role_has_permission("tier2_hunter", "user:delete"));

        // Built-in role deletion rejection
        let err = rbac.delete_custom_role("admin").unwrap_err();
        assert!(err.contains("Built-in role"));

        // Delete custom role
        assert!(rbac.delete_custom_role("tier2_hunter").unwrap());
        assert!(!rbac.role_has_permission("tier2_hunter", "hunt:execute"));
    }
}
