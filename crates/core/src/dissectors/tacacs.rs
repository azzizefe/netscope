// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a TACACS+ message (TCP 49) — Cisco's AAA protocol for device
/// administration. Byte 1 is the packet type: authentication, authorization
/// or accounting (RFC 8907).
pub fn dissect_tacacs(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.get(1) {
        Some(&t) => {
            let name = match t {
                1 => "Authentication",
                2 => "Authorization",
                3 => "Accounting",
                _ => "message",
            };
            format!("TACACS+ {name}")
        }
        None => "TACACS+ (truncated)".to_string(),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Tacacs,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authentication() {
        // version 0xc0, type 1 (authentication).
        let r = dissect_tacacs(None, None, 40000, 49, &[0xC0, 0x01, 0x01, 0x00]);
        assert_eq!(r.protocol, Protocol::Tacacs);
        assert_eq!(r.summary, "TACACS+ Authentication");
    }
}
