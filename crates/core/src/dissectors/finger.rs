// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Finger message (TCP 79) — a legacy user-lookup service. The
/// client sends a single line (a username, or empty for "who's logged in")
/// and the server replies with free text (RFC 1288).
pub fn dissect_finger(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let line = super::first_text_line(payload);
    let summary = if line.is_empty() {
        "Finger — list logged-in users".to_string()
    } else {
        format!("Finger — {}", super::truncate(&line, 50))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Finger,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_query() {
        let r = dissect_finger(None, None, 40000, 79, b"alice\r\n");
        assert_eq!(r.protocol, Protocol::Finger);
        assert_eq!(r.summary, "Finger — alice");
    }
}
