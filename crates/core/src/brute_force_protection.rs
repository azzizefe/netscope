// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

//! Brute-Force & IP Rate-Limiting Protection Engine (§1.2.1 - §1.2.4).
//!
//! Provides thread-safe, SQLite-compatible account lockout and IP ban protection:
//! - Account Lockout: 5 failed login attempts -> 15 min lock (§1.2.1)
//! - IP-based Rate Limit: 10 failed login attempts -> 30 min IP ban (§1.2.2)
//! - Audit Event Generation for lockouts and bans (§1.2.3)
//! - Manual Admin Unlock & Auto-Expiration (§1.2.4)

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_MAX_ACCOUNT_FAILED_ATTEMPTS: u32 = 5;
pub const DEFAULT_ACCOUNT_LOCKOUT_DURATION_SECS: u64 = 900; // 15 Minutes

pub const DEFAULT_MAX_IP_FAILED_ATTEMPTS: u32 = 10;
pub const DEFAULT_IP_LOCKOUT_DURATION_SECS: u64 = 1_800; // 30 Minutes

/// Status of an account or IP login check (§1.2.1, §1.2.2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LockoutStatus {
    Allowed,
    AccountLocked { remaining_secs: u64 },
    IpBanned { remaining_secs: u64 },
}

/// Audit event emitted on lockout or ban (§1.2.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockoutAuditEvent {
    pub timestamp_epoch: u64,
    pub event_type: String, // "ACCOUNT_LOCKOUT" or "IP_BAN"
    pub target: String,     // username or ip_address
    pub failed_attempts: u32,
    pub duration_secs: u64,
}

/// Account login failure tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountFailureRecord {
    pub username: String,
    pub failed_attempts: u32,
    pub locked_until_epoch: Option<u64>,
}

/// IP address login failure tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpFailureRecord {
    pub ip_address: String,
    pub failed_attempts: u32,
    pub banned_until_epoch: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct BruteForceProtector {
    inner: Arc<RwLock<ProtectorStore>>,
}

#[derive(Debug)]
struct ProtectorStore {
    account_failures: HashMap<String, AccountFailureRecord>,
    ip_failures: HashMap<String, IpFailureRecord>,
    max_account_attempts: u32,
    account_lock_secs: u64,
    max_ip_attempts: u32,
    ip_lock_secs: u64,
    audit_events: Vec<LockoutAuditEvent>,
}

impl Default for BruteForceProtector {
    fn default() -> Self {
        Self::new()
    }
}

impl BruteForceProtector {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(ProtectorStore {
                account_failures: HashMap::new(),
                ip_failures: HashMap::new(),
                max_account_attempts: DEFAULT_MAX_ACCOUNT_FAILED_ATTEMPTS,
                account_lock_secs: DEFAULT_ACCOUNT_LOCKOUT_DURATION_SECS,
                max_ip_attempts: DEFAULT_MAX_IP_FAILED_ATTEMPTS,
                ip_lock_secs: DEFAULT_IP_LOCKOUT_DURATION_SECS,
                audit_events: Vec::new(),
            })),
        }
    }

    fn now_epoch() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Check if login is allowed for user and IP (§1.2.1, §1.2.2).
    pub fn check_allowed(&self, username: &str, ip_address: &str) -> LockoutStatus {
        let now = Self::now_epoch();
        let store = self.inner.read();

        // 1. Check IP Ban (§1.2.2)
        if let Some(ip_rec) = store.ip_failures.get(ip_address) {
            if let Some(until) = ip_rec.banned_until_epoch {
                if until > now {
                    return LockoutStatus::IpBanned {
                        remaining_secs: until - now,
                    };
                }
            }
        }

        // 2. Check Account Lockout (§1.2.1)
        if let Some(acc_rec) = store.account_failures.get(username) {
            if let Some(until) = acc_rec.locked_until_epoch {
                if until > now {
                    return LockoutStatus::AccountLocked {
                        remaining_secs: until - now,
                    };
                }
            }
        }

        LockoutStatus::Allowed
    }

    /// Record a failed login attempt for user and IP (§1.2.1, §1.2.2, §1.2.3).
    pub fn record_failure(&self, username: &str, ip_address: &str) -> LockoutStatus {
        let now = Self::now_epoch();
        let mut store = self.inner.write();

        // Account failure record
        let max_acc = store.max_account_attempts;
        let acc_dur = store.account_lock_secs;
        let acc_rec = store
            .account_failures
            .entry(username.to_string())
            .or_insert_with(|| AccountFailureRecord {
                username: username.to_string(),
                failed_attempts: 0,
                locked_until_epoch: None,
            });

        acc_rec.failed_attempts += 1;
        let mut account_newly_locked = false;
        let mut account_remaining = 0;

        if acc_rec.failed_attempts >= max_acc {
            let until = now + acc_dur;
            acc_rec.locked_until_epoch = Some(until);
            account_newly_locked = true;
            account_remaining = acc_dur;
        }

        // IP failure record
        let max_ip = store.max_ip_attempts;
        let ip_dur = store.ip_lock_secs;
        let ip_rec = store
            .ip_failures
            .entry(ip_address.to_string())
            .or_insert_with(|| IpFailureRecord {
                ip_address: ip_address.to_string(),
                failed_attempts: 0,
                banned_until_epoch: None,
            });

        ip_rec.failed_attempts += 1;
        let mut ip_newly_banned = false;
        let mut ip_remaining = 0;

        if ip_rec.failed_attempts >= max_ip {
            let until = now + ip_dur;
            ip_rec.banned_until_epoch = Some(until);
            ip_newly_banned = true;
            ip_remaining = ip_dur;
        }

        // Audit log generation (§1.2.3)
        if account_newly_locked {
            store.audit_events.push(LockoutAuditEvent {
                timestamp_epoch: now,
                event_type: "ACCOUNT_LOCKOUT".to_string(),
                target: username.to_string(),
                failed_attempts: max_acc,
                duration_secs: acc_dur,
            });
        }

        if ip_newly_banned {
            store.audit_events.push(LockoutAuditEvent {
                timestamp_epoch: now,
                event_type: "IP_BAN".to_string(),
                target: ip_address.to_string(),
                failed_attempts: max_ip,
                duration_secs: ip_dur,
            });
        }

        if ip_newly_banned {
            LockoutStatus::IpBanned {
                remaining_secs: ip_remaining,
            }
        } else if account_newly_locked {
            LockoutStatus::AccountLocked {
                remaining_secs: account_remaining,
            }
        } else {
            LockoutStatus::Allowed
        }
    }

    /// Reset failure counters on successful login.
    pub fn record_success(&self, username: &str, ip_address: &str) {
        let mut store = self.inner.write();
        store.account_failures.remove(username);
        store.ip_failures.remove(ip_address);
    }

    /// Admin manual unlock for a username (§1.2.4).
    pub fn unlock_account(&self, username: &str) -> bool {
        let mut store = self.inner.write();
        store.account_failures.remove(username).is_some()
    }

    /// Admin manual unlock for an IP (§1.2.4).
    pub fn unlock_ip(&self, ip_address: &str) -> bool {
        let mut store = self.inner.write();
        store.ip_failures.remove(ip_address).is_some()
    }

    /// Get list of lockout audit events (§1.2.3).
    pub fn get_audit_events(&self) -> Vec<LockoutAuditEvent> {
        let store = self.inner.read();
        store.audit_events.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_lockout_trigger() {
        let protector = BruteForceProtector::new();
        let user = "victim_user";
        let ip = "192.168.1.100";

        for _ in 0..4 {
            let status = protector.record_failure(user, ip);
            assert_eq!(status, LockoutStatus::Allowed);
        }

        // 5th attempt triggers account lockout
        let status = protector.record_failure(user, ip);
        match status {
            LockoutStatus::AccountLocked { remaining_secs } => {
                assert!(remaining_secs <= DEFAULT_ACCOUNT_LOCKOUT_DURATION_SECS);
            }
            _ => panic!("Expected account locked"),
        }

        let check = protector.check_allowed(user, ip);
        assert!(matches!(check, LockoutStatus::AccountLocked { .. }));

        // Admin manual unlock
        assert!(protector.unlock_account(user));
        assert_eq!(protector.check_allowed(user, ip), LockoutStatus::Allowed);
    }

    #[test]
    fn test_ip_ban_trigger() {
        let protector = BruteForceProtector::new();
        let ip = "10.0.0.99";

        for i in 0..9 {
            protector.record_failure(&format!("user_{}", i), ip);
        }

        let status = protector.record_failure("user_9", ip);
        match status {
            LockoutStatus::IpBanned { remaining_secs } => {
                assert!(remaining_secs <= DEFAULT_IP_LOCKOUT_DURATION_SECS);
            }
            _ => panic!("Expected IP ban"),
        }

        assert!(protector.unlock_ip(ip));
        assert_eq!(
            protector.check_allowed("any_user", ip),
            LockoutStatus::Allowed
        );
    }
}
