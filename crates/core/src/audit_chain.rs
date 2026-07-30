// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

//! Cryptographic Audit Hash Chain Engine (§3.1.1, §3.1.2).
//!
//! Provides a thread-safe, append-only, SHA-256 cryptographic hash chain:
//! - Immutability: Every record stores the SHA-256 hash of the previous record (`prev_hash`)
//!   and its own composite hash (`entry_hash`) (§3.1.1)
//! - Chain Verification: Verification tool (`verify_integrity()`) that scans the entire
//!   log chain and flags tampered or altered audit records (§3.1.2)
//! - SQLite DDL Schema compatibility for zero-dependency persistence

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Represents a single cryptographic audit log entry (§3.1.1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEntry {
    pub id: u64,
    pub prev_hash: String,
    pub entry_hash: String,
    pub user_id: String,
    pub action: String,
    pub resource: String,
    pub ip_address: String,
    pub timestamp_epoch: u64,
    pub timestamp_iso: String,
}

/// Detailed verification result report for audit chain auditing (§3.1.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditVerificationReport {
    pub is_valid: bool,
    pub total_records: usize,
    pub tampered_index: Option<u64>,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct AuditChainManager {
    inner: Arc<RwLock<AuditStore>>,
}

#[derive(Debug)]
struct AuditStore {
    records: Vec<AuditEntry>,
    last_hash: String,
}

impl Default for AuditChainManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditChainManager {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(AuditStore {
                records: Vec::new(),
                last_hash: GENESIS_HASH.to_string(),
            })),
        }
    }

    fn now_epoch() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Compute SHA-256 hash of an entry (§3.1.1).
    pub fn compute_entry_hash(
        prev_hash: &str,
        user_id: &str,
        action: &str,
        resource: &str,
        ip_address: &str,
        timestamp_epoch: u64,
    ) -> String {
        let mut hasher = Sha256::new();
        let payload = format!(
            "{}:{}:{}:{}:{}:{}",
            prev_hash, user_id, action, resource, ip_address, timestamp_epoch
        );
        hasher.update(payload.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Append a new action to the audit chain (§3.1.1).
    pub fn log_action(
        &self,
        user_id: &str,
        action: &str,
        resource: &str,
        ip_address: &str,
    ) -> AuditEntry {
        let now = Self::now_epoch();
        let ts_iso = chrono::Utc::now().to_rfc3339();
        let mut store = self.inner.write();

        let id = store.records.len() as u64 + 1;
        let prev_hash = store.last_hash.clone();
        let entry_hash = Self::compute_entry_hash(&prev_hash, user_id, action, resource, ip_address, now);

        let entry = AuditEntry {
            id,
            prev_hash: prev_hash.clone(),
            entry_hash: entry_hash.clone(),
            user_id: user_id.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            ip_address: ip_address.to_string(),
            timestamp_epoch: now,
            timestamp_iso: ts_iso,
        };

        store.last_hash = entry_hash;
        store.records.push(entry.clone());
        entry
    }

    /// Verify chain integrity and check for any tampered records (§3.1.2).
    pub fn verify_integrity(&self) -> AuditVerificationReport {
        let store = self.inner.read();
        let mut expected_prev_hash = GENESIS_HASH.to_string();

        for (idx, entry) in store.records.iter().enumerate() {
            if entry.prev_hash != expected_prev_hash {
                return AuditVerificationReport {
                    is_valid: false,
                    total_records: store.records.len(),
                    tampered_index: Some(entry.id),
                    message: format!(
                        "Chain broken at record #{}: prev_hash mismatch. Expected {}, got {}",
                        entry.id, expected_prev_hash, entry.prev_hash
                    ),
                };
            }

            let recomputed = Self::compute_entry_hash(
                &entry.prev_hash,
                &entry.user_id,
                &entry.action,
                &entry.resource,
                &entry.ip_address,
                entry.timestamp_epoch,
            );

            if entry.entry_hash != recomputed {
                return AuditVerificationReport {
                    is_valid: false,
                    total_records: store.records.len(),
                    tampered_index: Some(entry.id),
                    message: format!(
                        "Tampered record detected at #{}: payload hash mismatch. Expected {}, got {}",
                        entry.id, recomputed, entry.entry_hash
                    ),
                };
            }

            expected_prev_hash = entry.entry_hash.clone();
        }

        AuditVerificationReport {
            is_valid: true,
            total_records: store.records.len(),
            tampered_index: None,
            message: format!("Audit chain integrity verified. All {} records are authentic and tamper-free.", store.records.len()),
        }
    }

    /// Get list of audit log records (§3.1.1).
    pub fn get_records(&self, limit: usize, offset: usize) -> Vec<AuditEntry> {
        let store = self.inner.read();
        store
            .records
            .iter()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get total count of logged audit events.
    pub fn count(&self) -> usize {
        let store = self.inner.read();
        store.records.len()
    }

    /// SQLite DDL Schema string for persistence (§3.1.1).
    pub fn get_sqlite_schema() -> &'static str {
        r#"
        CREATE TABLE IF NOT EXISTS audit_chain (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prev_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL,
            user_id TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            timestamp_epoch INTEGER NOT NULL,
            timestamp_iso TEXT NOT NULL
        );
        "#
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_chain_integrity() {
        let manager = AuditChainManager::new();

        manager.log_action("admin", "PCAP_EXPORT", "pcap/finance_q4.pcap", "10.0.1.47");
        manager.log_action("analyst1", "RULE_CREATE", "rules/detect_smb.json", "10.0.1.18");
        manager.log_action("operator", "SENSOR_RESTART", "sensor-01", "10.0.5.12");

        let report = manager.verify_integrity();
        assert!(report.is_valid);
        assert_eq!(report.total_records, 3);
        assert!(report.tampered_index.is_none());

        let records = manager.get_records(10, 0);
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].action, "PCAP_EXPORT");
        assert_eq!(records[1].action, "RULE_CREATE");
        assert_eq!(records[2].action, "SENSOR_RESTART");
    }

    #[test]
    fn test_audit_chain_tamper_detection() {
        let manager = AuditChainManager::new();

        manager.log_action("admin", "USER_DELETE", "user:stajyer", "127.0.0.1");
        manager.log_action("admin", "IP_BLOCK", "192.168.1.100", "127.0.0.1");

        // Simulate unauthorized tampering by altering the first record in-memory
        {
            let mut store = manager.inner.write();
            store.records[0].action = "USER_MODIFY".to_string(); // Alter payload
        }

        let report = manager.verify_integrity();
        assert!(!report.is_valid);
        assert_eq!(report.tampered_index, Some(1));
    }
}
