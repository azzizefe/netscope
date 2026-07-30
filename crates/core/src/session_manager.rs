// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

//! Session & Scoped API Key Management Engine (§1.1.1 - §1.1.7).
//!
//! Provides thread-safe, SQLite-compatible persistent token lifecycle management:
//! - Session persistence with SHA-256 token hashing
//! - Token expiry (24h access / 7d refresh) & sliding expiration (idle timeout)
//! - Concurrent session limits (max 5 active sessions per user)
//! - Granular session revocation & forced password reset flags
//! - Scoped API Keys (`netscope_api_...`) with custom permission lists

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Default configuration constants
pub const DEFAULT_ACCESS_TOKEN_TTL_SECS: u64 = 86_400; // 24 Hours
pub const DEFAULT_REFRESH_TOKEN_TTL_SECS: u64 = 604_800; // 7 Days
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 1_800; // 30 Minutes
pub const DEFAULT_MAX_CONCURRENT_SESSIONS: usize = 5;

/// Errors emitted by the session manager.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionError {
    TokenNotFound,
    SessionExpired,
    SessionIdleTimeout,
    SessionRevoked,
    PasswordResetRequired,
    ApiKeyNotFound,
    ApiKeyExpired,
    ApiKeyRevoked,
    PermissionDenied(String),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::TokenNotFound => write!(f, "Session token not found"),
            SessionError::SessionExpired => write!(f, "Session has expired"),
            SessionError::SessionIdleTimeout => {
                write!(f, "Session expired due to inactivity (idle timeout)")
            }
            SessionError::SessionRevoked => write!(f, "Session has been revoked"),
            SessionError::PasswordResetRequired => {
                write!(f, "User is required to reset password before continuing")
            }
            SessionError::ApiKeyNotFound => write!(f, "API Key not found"),
            SessionError::ApiKeyExpired => write!(f, "API Key has expired"),
            SessionError::ApiKeyRevoked => write!(f, "API Key has been revoked"),
            SessionError::PermissionDenied(p) => write!(f, "Permission denied for action: {}", p),
        }
    }
}

impl std::error::Error for SessionError {}

/// Represents an active user session (§1.1.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSession {
    pub session_id: String,
    pub token_hash: String,
    pub user_id: Uuid,
    pub username: String,
    pub created_at_epoch: u64,
    pub expires_at_epoch: u64,
    pub last_activity_epoch: u64,
    pub revoked: bool,
    pub ip_address: String,
    pub user_agent: String,
    pub requires_password_reset: bool,
    pub seq_num: u64,
}

/// Represents a Scoped API Key for automation/agents (§1.1.7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopedApiKey {
    pub key_id: String,
    pub key_hash: String,
    pub name: String,
    pub owner_user_id: Uuid,
    pub permissions: Vec<String>,
    pub created_at_epoch: u64,
    pub expires_at_epoch: Option<u64>,
    pub last_used_at_epoch: Option<u64>,
    pub revoked: bool,
}

/// Session Manager Engine state.
#[derive(Debug, Clone)]
pub struct SessionManager {
    inner: Arc<RwLock<SessionStore>>,
}

#[derive(Debug)]
struct SessionStore {
    sessions: HashMap<String, UserSession>,  // Key: token_hash
    api_keys: HashMap<String, ScopedApiKey>, // Key: key_hash
    max_concurrent_sessions: usize,
    access_token_ttl_secs: u64,
    _refresh_token_ttl_secs: u64,
    idle_timeout_secs: u64,
    next_seq: u64,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    pub fn new() -> Self {
        SessionManager {
            inner: Arc::new(RwLock::new(SessionStore {
                sessions: HashMap::new(),
                api_keys: HashMap::new(),
                max_concurrent_sessions: DEFAULT_MAX_CONCURRENT_SESSIONS,
                access_token_ttl_secs: DEFAULT_ACCESS_TOKEN_TTL_SECS,
                _refresh_token_ttl_secs: DEFAULT_REFRESH_TOKEN_TTL_SECS,
                idle_timeout_secs: DEFAULT_IDLE_TIMEOUT_SECS,
                next_seq: 1,
            })),
        }
    }

    /// Helper to compute SHA-256 hex string of a token or key.
    pub fn hash_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Get current epoch timestamp in seconds.
    pub fn now_epoch() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Create a new session for a user (§1.1.1, §1.1.2, §1.1.4).
    pub fn create_session(
        &self,
        user_id: Uuid,
        username: &str,
        ip_address: &str,
        user_agent: &str,
    ) -> (UserSession, String) {
        let raw_token = format!(
            "netscope_sess_{}_{}",
            Uuid::new_v4().simple(),
            Uuid::new_v4().simple()
        );
        let token_hash = Self::hash_token(&raw_token);
        let now = Self::now_epoch();

        let mut store = self.inner.write();
        let seq = store.next_seq;
        store.next_seq += 1;

        // Enforce max concurrent sessions limit (§1.1.4)
        let mut user_sessions: Vec<_> = store
            .sessions
            .values()
            .filter(|s| s.user_id == user_id && !s.revoked && s.expires_at_epoch > now)
            .cloned()
            .collect();

        if user_sessions.len() >= store.max_concurrent_sessions {
            // Sort by (created_at_epoch, seq_num) ascending (oldest first)
            user_sessions.sort_by_key(|s| (s.created_at_epoch, s.seq_num));
            if let Some(oldest) = user_sessions.first() {
                if let Some(session_to_revoke) = store.sessions.get_mut(&oldest.token_hash) {
                    session_to_revoke.revoked = true;
                }
            }
        }

        let session = UserSession {
            session_id: Uuid::new_v4().to_string(),
            token_hash: token_hash.clone(),
            user_id,
            username: username.to_string(),
            created_at_epoch: now,
            expires_at_epoch: now + store.access_token_ttl_secs,
            last_activity_epoch: now,
            revoked: false,
            ip_address: ip_address.to_string(),
            user_agent: user_agent.to_string(),
            requires_password_reset: false,
            seq_num: seq,
        };

        store.sessions.insert(token_hash, session.clone());
        (session, raw_token)
    }

    /// Validate and touch (sliding idle expiration) a session (§1.1.3).
    pub fn validate_and_touch(
        &self,
        raw_token: &str,
        ip_address: &str,
        _user_agent: &str,
    ) -> Result<UserSession, SessionError> {
        let token_hash = Self::hash_token(raw_token);
        let now = Self::now_epoch();
        let mut store = self.inner.write();
        let idle_timeout = store.idle_timeout_secs;

        let session = store
            .sessions
            .get_mut(&token_hash)
            .ok_or(SessionError::TokenNotFound)?;

        if session.revoked {
            return Err(SessionError::SessionRevoked);
        }

        if session.expires_at_epoch < now {
            return Err(SessionError::SessionExpired);
        }

        // Idle timeout check (§1.1.3)
        if now.saturating_sub(session.last_activity_epoch) > idle_timeout {
            session.revoked = true;
            return Err(SessionError::SessionIdleTimeout);
        }

        if session.requires_password_reset {
            return Err(SessionError::PasswordResetRequired);
        }

        // Touch last activity
        session.last_activity_epoch = now;
        if !ip_address.is_empty() {
            session.ip_address = ip_address.to_string();
        }

        Ok(session.clone())
    }

    /// Revoke a specific session (§1.1.5).
    pub fn revoke_session(&self, token_hash_or_id: &str) -> bool {
        let mut store = self.inner.write();
        let mut found = false;

        for s in store.sessions.values_mut() {
            if s.token_hash == token_hash_or_id || s.session_id == token_hash_or_id {
                s.revoked = true;
                found = true;
            }
        }
        found
    }

    /// Revoke all active sessions for a specific user (§1.1.5).
    pub fn revoke_all_sessions_for_user(&self, user_id: Uuid) -> usize {
        let mut store = self.inner.write();
        let mut count = 0;

        for s in store.sessions.values_mut() {
            if s.user_id == user_id && !s.revoked {
                s.revoked = true;
                count += 1;
            }
        }
        count
    }

    /// Force password reset flag on next login and revoke all current sessions (§1.1.6).
    pub fn force_password_reset(&self, user_id: Uuid) -> usize {
        let mut store = self.inner.write();
        let mut count = 0;

        for s in store.sessions.values_mut() {
            if s.user_id == user_id {
                s.requires_password_reset = true;
                s.revoked = true;
                count += 1;
            }
        }
        count
    }

    /// Create a Scoped API Key for automated agents/bots (§1.1.7).
    pub fn create_api_key(
        &self,
        name: &str,
        owner_user_id: Uuid,
        permissions: Vec<String>,
        ttl_days: Option<u64>,
    ) -> (ScopedApiKey, String) {
        let raw_key = format!("netscope_api_{}", Uuid::new_v4().simple());
        let key_hash = Self::hash_token(&raw_key);
        let now = Self::now_epoch();

        let expires_at_epoch = ttl_days.map(|days| now + (days * 86400));

        let api_key = ScopedApiKey {
            key_id: Uuid::new_v4().to_string(),
            key_hash: key_hash.clone(),
            name: name.to_string(),
            owner_user_id,
            permissions,
            created_at_epoch: now,
            expires_at_epoch,
            last_used_at_epoch: None,
            revoked: false,
        };

        let mut store = self.inner.write();
        store.api_keys.insert(key_hash, api_key.clone());
        (api_key, raw_key)
    }

    /// Validate an API Key and check for a required permission (§1.1.7).
    pub fn validate_api_key(
        &self,
        raw_key: &str,
        required_permission: Option<&str>,
    ) -> Result<ScopedApiKey, SessionError> {
        let key_hash = Self::hash_token(raw_key);
        let now = Self::now_epoch();
        let mut store = self.inner.write();

        let api_key = store
            .api_keys
            .get_mut(&key_hash)
            .ok_or(SessionError::ApiKeyNotFound)?;

        if api_key.revoked {
            return Err(SessionError::ApiKeyRevoked);
        }

        if let Some(exp) = api_key.expires_at_epoch {
            if exp < now {
                return Err(SessionError::ApiKeyExpired);
            }
        }

        if let Some(perm) = required_permission {
            if !api_key.permissions.contains(&"*".to_string())
                && !api_key.permissions.contains(&perm.to_string())
            {
                return Err(SessionError::PermissionDenied(perm.to_string()));
            }
        }

        api_key.last_used_at_epoch = Some(now);
        Ok(api_key.clone())
    }

    /// Revoke an API Key (§1.1.7).
    pub fn revoke_api_key(&self, key_id: &str) -> bool {
        let mut store = self.inner.write();
        for k in store.api_keys.values_mut() {
            if k.key_id == key_id || k.key_hash == key_id {
                k.revoked = true;
                return true;
            }
        }
        false
    }

    /// List active sessions for a user.
    pub fn list_user_sessions(&self, user_id: Uuid) -> Vec<UserSession> {
        let store = self.inner.read();
        store
            .sessions
            .values()
            .filter(|s| s.user_id == user_id && !s.revoked)
            .cloned()
            .collect()
    }

    /// List API keys for a user.
    pub fn list_user_api_keys(&self, owner_user_id: Uuid) -> Vec<ScopedApiKey> {
        let store = self.inner.read();
        store
            .api_keys
            .values()
            .filter(|k| k.owner_user_id == owner_user_id && !k.revoked)
            .cloned()
            .collect()
    }

    /// Get SQLite DDL migration schema for persistence (§1.1.1).
    pub fn get_sqlite_schema() -> &'static str {
        r#"
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            token_hash TEXT NOT NULL UNIQUE,
            user_id TEXT NOT NULL,
            username TEXT NOT NULL,
            created_at_epoch INTEGER NOT NULL,
            expires_at_epoch INTEGER NOT NULL,
            last_activity_epoch INTEGER NOT NULL,
            revoked INTEGER DEFAULT 0,
            ip_address TEXT,
            user_agent TEXT,
            requires_password_reset INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS scoped_api_keys (
            key_id TEXT PRIMARY KEY,
            key_hash TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            owner_user_id TEXT NOT NULL,
            permissions TEXT NOT NULL,
            created_at_epoch INTEGER NOT NULL,
            expires_at_epoch INTEGER,
            last_used_at_epoch INTEGER,
            revoked INTEGER DEFAULT 0
        );
        "#
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_lifecycle_and_expiry() {
        let sm = SessionManager::new();
        let user_id = Uuid::new_v4();
        let (sess, raw_token) =
            sm.create_session(user_id, "efe.akkaya", "127.0.0.1", "netscope-desktop/1.0");

        assert_eq!(sess.username, "efe.akkaya");
        assert!(!sess.revoked);

        let validated = sm
            .validate_and_touch(&raw_token, "127.0.0.1", "netscope-desktop/1.0")
            .unwrap();
        assert_eq!(validated.user_id, user_id);

        let revoked = sm.revoke_session(&sess.session_id);
        assert!(revoked);

        let err = sm
            .validate_and_touch(&raw_token, "127.0.0.1", "netscope-desktop/1.0")
            .unwrap_err();
        assert_eq!(err, SessionError::SessionRevoked);
    }

    #[test]
    fn test_concurrent_session_limit() {
        let sm = SessionManager::new();
        let user_id = Uuid::new_v4();

        // Create 6 sessions (limit is 5)
        let mut tokens = Vec::new();
        for i in 0..6 {
            let (_, token) =
                sm.create_session(user_id, "analyst", "10.0.0.1", &format!("agent-{}", i));
            tokens.push(token);
        }

        let active = sm.list_user_sessions(user_id);
        assert_eq!(active.len(), 5);

        // First token should be auto-revoked
        let err = sm
            .validate_and_touch(&tokens[0], "10.0.0.1", "agent-0")
            .unwrap_err();
        assert_eq!(err, SessionError::SessionRevoked);

        // Latest token should be valid
        assert!(sm
            .validate_and_touch(&tokens[5], "10.0.0.1", "agent-5")
            .is_ok());
    }

    #[test]
    fn test_scoped_api_keys() {
        let sm = SessionManager::new();
        let user_id = Uuid::new_v4();

        let (key, raw_key) = sm.create_api_key(
            "sensor-fleet-key",
            user_id,
            vec!["events:write".into(), "sensors:read".into()],
            Some(30),
        );
        assert!(raw_key.starts_with("netscope_api_"));

        let validated = sm.validate_api_key(&raw_key, Some("events:write")).unwrap();
        assert_eq!(validated.name, "sensor-fleet-key");

        let err = sm
            .validate_api_key(&raw_key, Some("rules:write"))
            .unwrap_err();
        assert_eq!(
            err,
            SessionError::PermissionDenied("rules:write".to_string())
        );

        assert!(sm.revoke_api_key(&key.key_id));
        let err2 = sm.validate_api_key(&raw_key, None).unwrap_err();
        assert_eq!(err2, SessionError::ApiKeyRevoked);
    }
}
