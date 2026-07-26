// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Shared helpers for SIGTRAN adaptation-layer dissectors (M2PA, M2UA, M3UA,
//! SUA). Each carries the same MTP3 User Adaptation header wrapping an upper-
//! layer payload, so this module extracts the common fields.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Produce a summary for a SIGTRAN adaptation-layer PDU.
pub fn summarize(
    name: &str,
    payload: &[u8],
    message_name: fn(u8) -> Option<&'static str>,
) -> String {
    if payload.len() < 8 {
        return format!("{name} — truncated header ({} bytes)", payload.len());
    }
    // SIGTRAN common header: version (1), reserved (1), message class (1),
    // message type (1), message length (4).
    let version = payload[0];
    let msg_class = payload[2];
    let msg_type = payload[3];
    if version != 1 {
        return format!("{name} — unknown version {version}");
    }
    let label = message_name(msg_type).unwrap_or("unknown message");
    let class_str = match msg_class {
        0 => "management",
        1 => "transfer",
        2 => "SS7 signalling network management",
        3 => "ASP state maintenance",
        4 => "ASP traffic maintenance",
        5 => "Q.921/Q.931 boundary primitive transport",
        6 => "MTP2 user adaptation",
        7 => "connectionless",
        8 => "connection-oriented",
        9 => "routing key management",
        10 => "interface identifier management",
        11 => "M2PA",
        _ => "reserved",
    };
    format!("{name} {label} ({class_str})")
}

#[cfg(test)]
pub mod test_helpers {
    /// Build a minimal SIGTRAN message for testing.
    pub fn sigtran(version: u8, msg_class: u8, msg_type: u16, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(version);
        v.push(0x00); // reserved
        v.push(msg_class);
        let [hi, lo] = msg_type.to_be_bytes();
        v.push(lo); // message type (low byte of u16 for most protocols)
        let len = (8 + body.len()) as u32;
        v.extend_from_slice(&len.to_be_bytes());
        v.extend_from_slice(body);
        v
    }
}
