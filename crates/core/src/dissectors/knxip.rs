// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a KNXnet/IP message (UDP 3671) — the IP side of the KNX building-
/// automation bus (lighting, HVAC, blinds). The header is length(1)=0x06,
/// version(1)=0x10, then a 2-byte service type.
pub fn dissect_knxip(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 4 && payload[0] == 0x06 && payload[1] == 0x10 {
        let svc = u16::from_be_bytes([payload[2], payload[3]]);
        let name = match svc {
            0x0201 => "Search Request",
            0x0202 => "Search Response",
            0x0205 => "Connect Request",
            0x0206 => "Connect Response",
            0x0420 => "Tunnelling Request",
            0x0421 => "Tunnelling Ack",
            0x0530 => "Routing Indication",
            _ => "message",
        };
        format!("KNXnet/IP {name}")
    } else {
        format!("KNXnet/IP ({})", super::bytes(payload.len() as u64))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Knxip,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_indication() {
        let r = dissect_knxip(None, None, 3671, 3671, &[0x06, 0x10, 0x05, 0x30]);
        assert_eq!(r.protocol, Protocol::Knxip);
        assert_eq!(r.summary, "KNXnet/IP Routing Indication");
    }
}
