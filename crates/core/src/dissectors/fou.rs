// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a FOU (Foo over UDP — Linux kernel direct IP protocol in UDP) packet (UDP 5555 / 5556).
pub fn dissect_fou(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.is_empty() {
        format!("FOU ({})", super::bytes(0u64))
    } else {
        let first_nibble = (payload[0] & 0xF0) >> 4;
        let inner_desc = match first_nibble {
            4 => "Direct IPv4 Payload",
            6 => "Direct IPv6 Payload",
            _ => "Direct IP Protocol Payload",
        };

        format!("FOU (Foo over UDP) — {inner_desc} ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Fou,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fou_ipv4_payload() {
        // IPv4 packet inside FOU (first byte 0x45)
        let payload = vec![0x45, 0x00, 0x00, 0x20];
        let res = dissect_fou(None, None, 5555, 5555, &payload);
        assert_eq!(res.protocol, Protocol::Fou);
        assert!(res.summary.contains("Direct IPv4 Payload"));
    }

    #[test]
    fn test_fou_empty_payload() {
        let payload = vec![];
        let res = dissect_fou(None, None, 5555, 5555, &payload);
        assert_eq!(res.protocol, Protocol::Fou);
        assert!(res.summary.contains("FOU (0 bytes)"));
    }
}
