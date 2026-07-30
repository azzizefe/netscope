// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! TLS secrets from an `SSLKEYLOGFILE`, parsed once and indexed.
//!
//! The format is one secret per line, as written by NSS, BoringSSL, OpenSSL
//! and everything built on them:
//!
//! ```text
//! CLIENT_RANDOM <64 hex> <96 hex>
//! CLIENT_TRAFFIC_SECRET_0 <64 hex> <64-96 hex>
//! ```
//!
//! The middle field is the ClientHello random, which is what ties a secret to
//! a connection seen on the wire.
//!
//! **Why this exists as a store rather than a file read.** The dissector needs
//! the secrets for one client random at each ServerHello. Reading and parsing
//! the whole file at that moment — which is what it used to do — costs a file
//! open and a full parse per TLS session: a browser keylog runs to thousands
//! of lines, and a capture holds hundreds of sessions. Parsing once into a map
//! turns that into one parse and a hash lookup.

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

/// Secrets for one connection, keyed by their keylog label.
pub type Secrets = HashMap<String, Vec<u8>>;

/// What a load found, so the UI can say whether it will actually decrypt
/// anything rather than silently doing nothing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeyLogStats {
    /// Connections the store can now decrypt.
    pub sessions: usize,
    /// Secret lines accepted.
    pub secrets: usize,
    /// Lines that were not comments and not parseable.
    pub rejected: usize,
}

#[derive(Debug, Default)]
pub struct KeyLog {
    by_random: HashMap<[u8; 32], Secrets>,
}

impl KeyLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add every secret in `text`, keeping what is already there.
    ///
    /// Merging rather than replacing is deliberate: a keylog is appended to as
    /// the browser runs, and an analyst may drop one file from Chrome and
    /// another from curl. Replacing on each load would silently discard the
    /// first, and the symptom — some flows decrypt, some do not — is very hard
    /// to attribute back to the load.
    pub fn merge_from(&mut self, text: &str) -> KeyLogStats {
        let mut stats = KeyLogStats::default();
        let before = self.by_random.len();

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let (Some(label), Some(random_hex), Some(secret_hex), None) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                stats.rejected += 1;
                continue;
            };

            // The client random is exactly 32 bytes. A line whose middle field
            // is any other length is not addressing a connection we could look
            // up, and indexing it under a truncated or padded key would make it
            // silently unreachable rather than visibly wrong.
            let Some(random) = decode_hex_32(random_hex) else {
                stats.rejected += 1;
                continue;
            };
            let Some(secret) = decode_hex(secret_hex) else {
                stats.rejected += 1;
                continue;
            };
            if secret.is_empty() {
                stats.rejected += 1;
                continue;
            }

            self.by_random
                .entry(random)
                .or_default()
                .insert(label.to_ascii_uppercase(), secret);
            stats.secrets += 1;
        }

        stats.sessions = self.by_random.len().saturating_sub(before);
        stats
    }

    pub fn secrets_for(&self, client_random: &[u8; 32]) -> Option<&Secrets> {
        self.by_random.get(client_random)
    }

    /// Connections this log can address.
    pub fn session_count(&self) -> usize {
        self.by_random.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_random.is_empty()
    }
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let bytes = decode_hex(s)?;
    bytes.try_into().ok()
}

// ── Process-wide store ──────────────────────────────────────────────────────
//
// Process-wide rather than thread-local: the keylog is loaded from the UI
// thread and read from the capture thread, so a `thread_local!` store — which
// is what the TLS session table uses — would load secrets the dissector never
// sees.

fn store() -> &'static RwLock<KeyLog> {
    static STORE: OnceLock<RwLock<KeyLog>> = OnceLock::new();
    STORE.get_or_init(|| RwLock::new(KeyLog::new()))
}

/// Add the secrets in `text` to the process-wide store.
pub fn load(text: &str) -> KeyLogStats {
    let mut guard = store().write().unwrap_or_else(|e| e.into_inner());
    guard.merge_from(text)
}

/// Forget every loaded secret.
///
/// Worth having on its own: the secrets decrypt a user's own traffic, and an
/// analyst who has finished with a capture should be able to drop them without
/// restarting.
pub fn clear() {
    let mut guard = store().write().unwrap_or_else(|e| e.into_inner());
    *guard = KeyLog::new();
}

/// How many connections the store can currently address.
pub fn session_count() -> usize {
    store()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .session_count()
}

/// Secrets for one client random, from the store or — failing that — from the
/// `SSLKEYLOGFILE` environment variable.
///
/// The environment fallback is kept so a shell that already exports the
/// variable keeps working without anyone loading a file through the UI. It is
/// only consulted when the store has nothing, so the loaded file wins.
pub fn secrets_for(client_random: &[u8; 32]) -> Option<Secrets> {
    if let Some(found) = store()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .secrets_for(client_random)
    {
        return Some(found.clone());
    }

    let path = std::env::var("SSLKEYLOGFILE").ok()?;
    let content = std::fs::read_to_string(path).ok()?;
    let mut log = KeyLog::new();
    log.merge_from(&content);
    log.secrets_for(client_random).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn hex32(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    #[test]
    fn a_client_random_line_is_indexed_by_its_random() {
        let mut log = KeyLog::new();
        let stats = log.merge_from(&format!(
            "CLIENT_RANDOM {} {}\n",
            hex32(0xaa),
            "bb".repeat(48)
        ));

        assert_eq!(stats.sessions, 1);
        assert_eq!(stats.secrets, 1);
        assert_eq!(stats.rejected, 0);

        let secrets = log.secrets_for(&random(0xaa)).expect("indexed");
        assert_eq!(secrets["CLIENT_RANDOM"].len(), 48);
        assert!(log.secrets_for(&random(0xbb)).is_none());
    }

    #[test]
    fn several_labels_for_one_connection_land_together() {
        let mut log = KeyLog::new();
        let r = hex32(0x11);
        log.merge_from(&format!(
            "CLIENT_TRAFFIC_SECRET_0 {r} {}\nSERVER_TRAFFIC_SECRET_0 {r} {}\n",
            "01".repeat(32),
            "02".repeat(32),
        ));

        let secrets = log.secrets_for(&random(0x11)).expect("indexed");
        assert_eq!(secrets.len(), 2);
        assert!(secrets.contains_key("CLIENT_TRAFFIC_SECRET_0"));
        assert!(secrets.contains_key("SERVER_TRAFFIC_SECRET_0"));
    }

    /// A keylog grows while the browser runs, and an analyst may drop one file
    /// from Chrome and another from curl. Replacing on load would discard the
    /// first, and "some flows decrypt and some do not" is very hard to trace
    /// back to that.
    #[test]
    fn a_second_load_adds_to_the_first_rather_than_replacing_it() {
        let mut log = KeyLog::new();
        log.merge_from(&format!(
            "CLIENT_RANDOM {} {}\n",
            hex32(0x01),
            "aa".repeat(48)
        ));
        log.merge_from(&format!(
            "CLIENT_RANDOM {} {}\n",
            hex32(0x02),
            "bb".repeat(48)
        ));

        assert_eq!(log.session_count(), 2);
        assert!(log.secrets_for(&random(0x01)).is_some());
        assert!(log.secrets_for(&random(0x02)).is_some());
    }

    #[test]
    fn comments_and_blank_lines_are_not_failures() {
        let mut log = KeyLog::new();
        let stats = log.merge_from("# generated by NSS\n\n   \n");
        assert_eq!(stats, KeyLogStats::default());
    }

    /// A malformed line must be counted, not indexed. Indexing a truncated
    /// random under a padded key makes the secret silently unreachable, which
    /// looks exactly like "decryption does not work" with nothing to blame.
    #[test]
    fn a_malformed_line_is_rejected_and_counted() {
        let mut log = KeyLog::new();
        let stats = log.merge_from(&format!(
            "CLIENT_RANDOM {} {}\n\
             CLIENT_RANDOM tooshort {}\n\
             CLIENT_RANDOM {} nothex!!\n\
             CLIENT_RANDOM {}\n\
             CLIENT_RANDOM {} {} extra\n",
            hex32(0x33),
            "cc".repeat(48),
            "dd".repeat(48),
            hex32(0x44),
            hex32(0x55),
            hex32(0x66),
            "ee".repeat(48),
        ));

        assert_eq!(stats.secrets, 1, "only the well-formed line is usable");
        assert_eq!(stats.rejected, 4);
        assert_eq!(log.session_count(), 1);
    }

    /// An odd number of hex characters cannot be bytes.
    #[test]
    fn an_odd_length_secret_is_rejected() {
        let mut log = KeyLog::new();
        let stats = log.merge_from(&format!("CLIENT_RANDOM {} abc\n", hex32(0x77)));
        assert_eq!(stats.rejected, 1);
        assert!(log.is_empty());
    }

    /// Labels are matched case-insensitively against what the dissector asks
    /// for, so they are normalised on the way in rather than at every lookup.
    #[test]
    fn labels_are_normalised_to_upper_case() {
        let mut log = KeyLog::new();
        log.merge_from(&format!(
            "client_random {} {}\n",
            hex32(0x88),
            "ff".repeat(48)
        ));
        let secrets = log.secrets_for(&random(0x88)).unwrap();
        assert!(secrets.contains_key("CLIENT_RANDOM"));
    }

    #[test]
    fn the_last_secret_for_a_label_wins() {
        let mut log = KeyLog::new();
        let r = hex32(0x99);
        log.merge_from(&format!(
            "CLIENT_RANDOM {r} {}\nCLIENT_RANDOM {r} {}\n",
            "11".repeat(48),
            "22".repeat(48),
        ));
        let secrets = log.secrets_for(&random(0x99)).unwrap();
        assert_eq!(secrets["CLIENT_RANDOM"][0], 0x22);
    }
}
