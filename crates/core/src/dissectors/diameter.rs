// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Diameter message (TCP/SCTP 3868) — the AAA protocol that replaced
/// RADIUS, central to mobile-network billing and policy. Byte 0 is the version
/// (0x01); byte 4 holds command flags and bytes 5..8 the command code (RFC 6733).
pub fn dissect_diameter(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 && payload[0] == 0x01 {
        let is_request = payload[4] & 0x80 != 0;
        let code = u32::from_be_bytes([0, payload[5], payload[6], payload[7]]);
        let name = match code {
            257 => "Capabilities-Exchange",
            258 => "Re-Auth",
            271 => "Accounting",
            280 => "Device-Watchdog",
            282 => "Disconnect-Peer",
            _ => "command",
        };
        let dir = if is_request { "Request" } else { "Answer" };
        format!("Diameter {name} {dir} (code {code})")
    } else {
        format!("Diameter ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Diameter,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watchdog_request() {
        // version 1, length (3), flags 0x80 (request), code 280.
        let r = dissect_diameter(
            None,
            None,
            40000,
            3868,
            &[0x01, 0x00, 0x00, 0x14, 0x80, 0x00, 0x01, 0x18],
        );
        assert_eq!(r.protocol, Protocol::Diameter);
        assert!(r.summary.contains("Device-Watchdog Request"), "{}", r.summary);
    }
}
