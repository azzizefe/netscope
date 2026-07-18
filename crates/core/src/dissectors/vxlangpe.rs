// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a VXLAN-GPE packet (UDP 4790) — Generic Protocol Extension, which
/// adds a next-protocol field to VXLAN so an overlay can carry IP or a service
/// header directly, not just Ethernet. Byte 3 is that next protocol, bytes
/// 4..7 the VNI.
pub fn dissect_vxlangpe(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let next = match payload[3] {
            1 => "IPv4",
            2 => "IPv6",
            3 => "Ethernet",
            4 => "NSH (service chain)",
            5 => "MPLS",
            _ => "payload",
        };
        let vni = u32::from_be_bytes([0, payload[4], payload[5], payload[6]]);
        format!("VXLAN-GPE — VNI {vni}, carrying {next}")
    } else {
        "VXLAN-GPE (truncated)".to_string()
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::VxlanGpe,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carrying_nsh() {
        // flags, reserved(2), next protocol 4 (NSH), VNI 300.
        let p = [0x0C, 0x00, 0x00, 0x04, 0x00, 0x01, 0x2C, 0x00];
        let r = dissect_vxlangpe(None, None, 40000, 4790, &p);
        assert_eq!(r.protocol, Protocol::VxlanGpe);
        assert_eq!(
            r.summary,
            "VXLAN-GPE — VNI 300, carrying NSH (service chain)"
        );
    }
}
