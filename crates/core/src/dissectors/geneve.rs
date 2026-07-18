// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Geneve packet (UDP 6081) — a flexible network-virtualisation
/// overlay (a VXLAN successor). Bytes 2..4 are the protocol type of the inner
/// frame and bytes 4..7 the 24-bit VNI (RFC 8926).
pub fn dissect_geneve(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let proto_type = u16::from_be_bytes([payload[2], payload[3]]);
        let vni = u32::from_be_bytes([0, payload[4], payload[5], payload[6]]);
        let inner = match proto_type {
            0x6558 => "Ethernet",
            0x0800 => "IPv4",
            0x86DD => "IPv6",
            _ => "payload",
        };
        format!("Geneve — VNI {vni}, carrying {inner}")
    } else {
        "Geneve (truncated)".to_string()
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Geneve,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethernet_overlay() {
        // ver/optlen, flags, proto 0x6558 (Ethernet), VNI 100.
        let p = [0x00, 0x00, 0x65, 0x58, 0x00, 0x00, 0x64, 0x00];
        let r = dissect_geneve(None, None, 40000, 6081, &p);
        assert_eq!(r.protocol, Protocol::Geneve);
        assert_eq!(r.summary, "Geneve — VNI 100, carrying Ethernet");
    }
}
