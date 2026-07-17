// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an LDP message (TCP/UDP 646) — how MPLS routers distribute the
/// labels that build label-switched paths. After the 10-byte PDU header the
/// message type (with its high U-bit masked off) names the message (RFC 5036).
pub fn dissect_ldp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 12 {
        let msg_type = u16::from_be_bytes([payload[10], payload[11]]) & 0x7FFF;
        let name = match msg_type {
            0x0001 => "Notification",
            0x0100 => "Hello",
            0x0200 => "Initialization",
            0x0201 => "KeepAlive",
            0x0300 => "Address",
            0x0301 => "Address Withdraw",
            0x0400 => "Label Mapping",
            0x0401 => "Label Request",
            0x0403 => "Label Withdraw",
            0x0404 => "Label Release",
            _ => "message",
        };
        format!("LDP {name}")
    } else {
        "LDP (truncated)".to_string()
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ldp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello() {
        // version(2) len(2) lsr-id(4) label-space(2) then msg type 0x0100 (Hello).
        let mut p = vec![0x00, 0x01, 0x00, 0x1c];
        p.extend_from_slice(&[10, 0, 0, 1]); // LSR ID
        p.extend_from_slice(&[0x00, 0x00]); // label space
        p.extend_from_slice(&[0x01, 0x00]); // message type: Hello
        let r = dissect_ldp(None, None, 646, 646, &p);
        assert_eq!(r.protocol, Protocol::Ldp);
        assert_eq!(r.summary, "LDP Hello");
    }
}
