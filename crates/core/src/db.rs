// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use chrono::Utc;
use rusqlite::{params, Connection, Result};
use std::path::PathBuf;

/// A URL-safe random password (96 bits, hex-encoded) for first-run seeding.
fn random_password() -> String {
    let mut bytes = [0u8; 12];
    let _ = getrandom::getrandom(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Bridge a crypto (`anyhow`) error into the `rusqlite::Error` this module
/// returns, so password hashing composes with the SQLite call sites.
fn to_db_err(e: anyhow::Error) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(e.into())
}

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn open() -> Result<Self> {
        let dir = crate::config::config_dir().unwrap_or_else(|| PathBuf::from("."));
        let _ = std::fs::create_dir_all(&dir);
        let db_path = dir.join("netscope.db");

        let conn = Connection::open(db_path)?;
        // Wait rather than fail immediately if the TUI and the REST API touch
        // the DB at the same time.
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let db = Database { conn };
        db.init_tables()?;
        db.seed_users()?;
        Ok(db)
    }

    fn init_tables(&self) -> Result<()> {
        // 1. Users Table
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL
            )",
            [],
        )?;

        // 2. Bookmarks Table
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS bookmarks (
                id INTEGER PRIMARY KEY,
                capture_file TEXT NOT NULL,
                packet_index INTEGER NOT NULL,
                tag TEXT NOT NULL,
                UNIQUE(capture_file, packet_index)
            )",
            [],
        )?;

        // 3. Annotations Table
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS annotations (
                id INTEGER PRIMARY KEY,
                capture_file TEXT NOT NULL,
                packet_index INTEGER NOT NULL,
                comment TEXT NOT NULL,
                username TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )",
            [],
        )?;

        // 4. Audit Log Table
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                capture_file TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )",
            [],
        )?;

        Ok(())
    }

    fn seed_users(&self) -> Result<()> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?;

        if count == 0 {
            // First run only: create the three RBAC accounts with RANDOM
            // passwords, hashed with Argon2id, and print them once. No fixed
            // credentials are compiled into the binary or committed to the repo.
            let creds = [
                ("admin", "Admin", random_password()),
                ("analyst", "Analyst", random_password()),
                ("viewer", "Viewer", random_password()),
            ];
            for (username, role, password) in &creds {
                let hash = crate::crypto::hash_password(password).map_err(to_db_err)?;
                self.conn.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                    params![username, hash, role],
                )?;
            }

            eprintln!(
                "\n=== netscope: first-run account setup ===\n\
                 Generated random passwords for the optional local REST API accounts.\n\
                 They are shown ONCE and are not recoverable — save the ones you need\n\
                 (the API is off by default and binds to 127.0.0.1 only):\n\n  \
                 admin    {}\n  analyst  {}\n  viewer   {}\n\
                 =========================================\n",
                creds[0].2, creds[1].2, creds[2].2,
            );
        }
        Ok(())
    }

    // --- Authentication ---

    /// Verify a username/password pair against the stored Argon2 hash.
    /// Returns the user's role on success; `None` for an unknown user or a
    /// wrong password.
    pub fn authenticate(&self, username: &str, password: &str) -> Result<Option<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT password_hash, role FROM users WHERE username = ?")?;
        let mut rows = stmt.query(params![username])?;
        if let Some(row) = rows.next()? {
            let stored_hash: String = row.get(0)?;
            let role: String = row.get(1)?;
            if crate::crypto::verify_password(password, &stored_hash) {
                return Ok(Some(role));
            }
        }
        Ok(None)
    }

    /// Insert a user, or replace an existing one's password and role. Hashes
    /// with Argon2id like the seed path. Used for administrative bootstrapping
    /// and by tests that need a known password.
    pub fn upsert_user(&self, username: &str, password: &str, role: &str) -> Result<()> {
        let hash = crate::crypto::hash_password(password).map_err(to_db_err)?;
        self.conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?1, ?2, ?3)
             ON CONFLICT(username) DO UPDATE SET password_hash = ?2, role = ?3",
            params![username, hash, role],
        )?;
        Ok(())
    }

    // --- Bookmarks ---
    pub fn add_bookmark(&self, capture_file: &str, packet_index: i64, tag: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO bookmarks (capture_file, packet_index, tag) VALUES (?, ?, ?)",
            params![capture_file, packet_index, tag],
        )?;
        Ok(())
    }

    pub fn delete_bookmark(&self, capture_file: &str, packet_index: i64) -> Result<()> {
        self.conn.execute(
            "DELETE FROM bookmarks WHERE capture_file = ? AND packet_index = ?",
            params![capture_file, packet_index],
        )?;
        Ok(())
    }

    pub fn list_bookmarks(&self, capture_file: &str) -> Result<Vec<(i64, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT packet_index, tag FROM bookmarks WHERE capture_file = ?")?;
        let rows = stmt.query_map(params![capture_file], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let mut results = Vec::new();
        for r in rows {
            results.push(r?);
        }
        Ok(results)
    }

    // --- Annotations ---
    pub fn add_annotation(
        &self,
        capture_file: &str,
        packet_index: i64,
        comment: &str,
        username: &str,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO annotations (capture_file, packet_index, comment, username, timestamp) VALUES (?, ?, ?, ?, ?)",
            params![capture_file, packet_index, comment, username, now],
        )?;
        Ok(())
    }

    pub fn list_annotations(
        &self,
        capture_file: &str,
    ) -> Result<Vec<(i64, String, String, String)>> {
        let mut stmt = self.conn.prepare("SELECT packet_index, comment, username, timestamp FROM annotations WHERE capture_file = ?")?;
        let rows = stmt.query_map(params![capture_file], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?;
        let mut results = Vec::new();
        for r in rows {
            results.push(r?);
        }
        Ok(results)
    }

    // --- Audit Log ---
    pub fn log_action(&self, username: &str, action: &str, capture_file: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO audit_log (username, action, capture_file, timestamp) VALUES (?, ?, ?, ?)",
            params![username, action, capture_file, now],
        )?;
        Ok(())
    }

    pub fn list_audit_logs(&self) -> Result<Vec<(String, String, String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT username, action, capture_file, timestamp FROM audit_log ORDER BY id DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?;
        let mut results = Vec::new();
        for r in rows {
            results.push(r?);
        }
        Ok(results)
    }
}
