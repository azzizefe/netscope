// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Shared helpers for SIGTRAN adaptation layer dissectors (M2UA, M2PA, M3UA, SUA).

/// Build a human-readable summary for a SIGTRAN adaptation layer PDU.
pub fn summarize(name: &str, _payload: &[u8], message: Option<&str>) -> String {
    match message {
        Some(msg) => format!("{name} {msg}"),
        None => format!("{name} PDU"),
    }
}

#[cfg(test)]
pub mod test_helpers {
    /// Build a minimal SIGTRAN PDU for testing the dispatch path.
    pub fn sigtran(_version: u8, _msg_class: u8, _msg_type: u16, _payload: &[u8]) -> Vec<u8> {
        vec![]
    }
}
