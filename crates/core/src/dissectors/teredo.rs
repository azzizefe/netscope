// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Teredo packet (UDP 3544) — a transition tech that tunnels IPv6
/// through IPv4 NATs. The payload is either an IPv6 packet or a small
/// indicator header (RFC 4380).
pub fn dissect_teredo(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.first() {
        Some(b) if b >> 4 == 6 => "Teredo — tunnelled IPv6 packet".to_string(),
        Some(0x00) => match payload.get(1) {
            Some(0x00) => "Teredo authentication indicator".to_string(),
            Some(0x01) => "Teredo origin indicator".to_string(),
            _ => "Teredo indicator".to_string(),
        },
        _ => format!("Teredo ({} bytes)", payload.len()),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Teredo,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnelled_ipv6() {
        // First nibble 6 = IPv6.
        let r = dissect_teredo(None, None, 3544, 40000, &[0x60, 0x00, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Teredo);
        assert!(r.summary.contains("IPv6"), "{}", r.summary);
    }
}
