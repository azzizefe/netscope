// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The four-letter MGCP verbs (RFC 3435), used to tell a command from a
/// numeric response.
const VERBS: [&str; 9] = [
    "CRCX", "MDCX", "DLCX", "RQNT", "NTFY", "AUEP", "AUCX", "RSIP", "EPCF",
];

/// Dissect an MGCP message (UDP 2427/2727) — how a call agent controls VoIP
/// media gateways. The first token is a command verb or a numeric response.
pub fn dissect_mgcp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let line = super::first_text_line(payload);
    let tok = line.split_whitespace().next().unwrap_or("");
    let summary = if VERBS.contains(&tok) {
        format!("MGCP {tok} (command)")
    } else if !tok.is_empty() && tok.chars().all(|c| c.is_ascii_digit()) {
        format!("MGCP response {tok}")
    } else {
        format!("MGCP ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Mgcp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_connection() {
        let r = dissect_mgcp(None, None, 40000, 2427, b"CRCX 1201 aaln/1@gw.example.com MGCP 1.0\r\n");
        assert_eq!(r.protocol, Protocol::Mgcp);
        assert_eq!(r.summary, "MGCP CRCX (command)");
    }

    #[test]
    fn response() {
        let r = dissect_mgcp(None, None, 2427, 40000, b"200 1201 OK\r\n");
        assert_eq!(r.summary, "MGCP response 200");
    }
}
