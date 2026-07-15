// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use rusqlite::{params, Connection, Result};
use std::path::PathBuf;
use chrono::Utc;

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn open() -> Result<Self> {
        let dir = crate::config::config_dir()
            .unwrap_or_else(|| PathBuf::from("."));
        let _ = std::fs::create_dir_all(&dir);
        let db_path = dir.join("netscope.db");
        
        let conn = Connection::open(db_path)?;
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
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM users",
            [],
            |row| row.get(0),
        )?;

        if count == 0 {
            // Hash helper: SHA-256 (same as in api_server.rs)
            let hash_pwd = |pwd: &str| {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(pwd.as_bytes());
                format!("{:x}", hasher.finalize())
            };

            // Seed admin, analyst, viewer
            self.conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                params!["admin", hash_pwd("admin123"), "Admin"],
            )?;
            self.conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                params!["analyst", hash_pwd("analyst123"), "Analyst"],
            )?;
            self.conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                params!["viewer", hash_pwd("viewer123"), "Viewer"],
            )?;
        }
        Ok(())
    }

    // --- Authentication ---
    pub fn get_user_role(&self, username: &str, password_hash: &str) -> Result<Option<String>> {
        let mut stmt = self.conn.prepare("SELECT role FROM users WHERE username = ? AND password_hash = ?")?;
        let mut rows = stmt.query(params![username, password_hash])?;
        if let Some(row) = rows.next()? {
            let role: String = row.get(0)?;
            Ok(Some(role))
        } else {
            Ok(None)
        }
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
        let mut stmt = self.conn.prepare("SELECT packet_index, tag FROM bookmarks WHERE capture_file = ?")?;
        let rows = stmt.query_map(params![capture_file], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
        let mut results = Vec::new();
        for r in rows {
            results.push(r?);
        }
        Ok(results)
    }

    // --- Annotations ---
    pub fn add_annotation(&self, capture_file: &str, packet_index: i64, comment: &str, username: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO annotations (capture_file, packet_index, comment, username, timestamp) VALUES (?, ?, ?, ?, ?)",
            params![capture_file, packet_index, comment, username, now],
        )?;
        Ok(())
    }

    pub fn list_annotations(&self, capture_file: &str) -> Result<Vec<(i64, String, String, String)>> {
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
        let mut stmt = self.conn.prepare("SELECT username, action, capture_file, timestamp FROM audit_log ORDER BY id DESC")?;
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
