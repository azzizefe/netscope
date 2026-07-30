// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a VRRP advertisement (IP protocol 112) — how routers share a
/// virtual IP for gateway redundancy. Byte 0 packs version and type, byte 1
/// is the virtual router id, byte 2 the priority (RFC 5798).
pub fn dissect_vrrp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 3 {
        let version = payload[0] >> 4;
        let vrid = payload[1];
        let priority = payload[2];
        let note = match priority {
            255 => " (owner)",
            0 => " (releasing)",
            _ => "",
        };
        format!("VRRPv{version} Advertisement — VRID {vrid}, priority {priority}{note}")
    } else {
        "VRRP (truncated)".to_string()
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Vrrp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertisement() {
        // v3, type 1, VRID 10, priority 100.
        let r = dissect_vrrp(None, None, &[0x31, 0x0A, 0x64, 0x00]);
        assert_eq!(r.protocol, Protocol::Vrrp);
        assert_eq!(r.summary, "VRRPv3 Advertisement — VRID 10, priority 100");
    }
}
