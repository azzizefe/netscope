// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Flags, reserved, next protocol, reserved, then the VNI.
const HEADER: usize = 8;

/// Next-protocol values (draft-ietf-nvo3-vxlan-gpe).
const NEXT_IPV4: u8 = 1;
const NEXT_IPV6: u8 = 2;
const NEXT_ETHERNET: u8 = 3;
const NEXT_NSH: u8 = 4;
const NEXT_MPLS: u8 = 5;

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
    // Unlike plain VXLAN, this one names what it carries, so there is no
    // guessing to do — dispatch on the next-protocol field.
    if payload.len() >= HEADER {
        let vni = u32::from_be_bytes([0, payload[4], payload[5], payload[6]]);
        if let Some(inner) = payload.get(HEADER..) {
            if !inner.is_empty() {
                let unwrapped = match payload[3] {
                    NEXT_IPV4 => Some(super::dispatch_l3(0x0800, inner, 0)),
                    NEXT_IPV6 => Some(super::dispatch_l3(0x86DD, inner, 0)),
                    NEXT_ETHERNET => Some(super::dissect(inner)),
                    NEXT_NSH => Some(super::nsh::dissect_nsh(inner)),
                    _ => None,
                };
                if let Some(mut r) = unwrapped {
                    r.summary = format!("VXLAN-GPE VNI {vni} · {}", r.summary);
                    r.src_port = Some(src_port);
                    r.dst_port = Some(dst_port);
                    return r;
                }
            }
        }
    }

    let summary = if payload.len() >= HEADER {
        let next = match payload[3] {
            NEXT_IPV4 => "IPv4",
            NEXT_IPV6 => "IPv6",
            NEXT_ETHERNET => "Ethernet",
            NEXT_NSH => "NSH (service chain)",
            NEXT_MPLS => "MPLS",
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
