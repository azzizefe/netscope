// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Unix-to-Unix Copy Protocol (UUCP, TCP 540) frame.
pub fn dissect_uucp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if let Ok(s) = std::str::from_utf8(payload) {
        if s.contains("Shere") {
            "UUCP Handshake · Shere".to_string()
        } else if s.starts_with('S') {
            "UUCP Send File".to_string()
        } else if s.starts_with('R') {
            "UUCP Receive File".to_string()
        } else if s.starts_with('X') {
            "UUCP Execute Command".to_string()
        } else if s.starts_with('H') {
            "UUCP Hangup".to_string()
        } else {
            format!("UUCP Session ({})", super::bytes(payload.len() as u64))
        }
    } else {
        format!("UUCP ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Uucp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uucp_handshake() {
        let payload = b"\x14Shere=myhost\x00";
        let r = dissect_uucp(None, None, 40000, 540, payload);
        assert_eq!(r.protocol, Protocol::Uucp);
        assert_eq!(r.summary, "UUCP Handshake · Shere");
    }
}
