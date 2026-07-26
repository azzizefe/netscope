// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! LonTalk / ANSI 709.1 protocol helpers.
//!
//! LonTalk is the protocol spoken by Echelon LonWorks devices on control
//! networks. CNIP tunnels LonTalk frames inside IP/UDP; this module decodes
//! the common frame fields so the CNIP dissector can describe what is inside.

/// Describe a LonTalk frame.
pub fn describe(payload: &[u8]) -> String {
    if payload.is_empty() {
        return "LonTalk — empty frame".to_string();
    }
    let pdu_type = payload[0] & 0x0F;
    let kind = match pdu_type {
        0 => "ACK",
        1 => "Request/Response",
        2 => "Response",
        3 => "Unacknowledged",
        4 => "Unacknowledged repeat",
        5 => "Reminder",
        8 => "Network management",
        9 => "Network diagnostic",
        12 => "Application",
        _ => "unknown PDU",
    };
    format!("LonTalk {kind} ({len} bytes)", len = payload.len())
}
