// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a DoIP message (UDP/TCP 13400) — Diagnostics over IP, how a tester
/// reaches a vehicle's ECUs over Ethernet. Byte 0 is the version, bytes 2..4
/// the payload type (ISO 13400).
pub fn dissect_doip(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        let ptype = u16::from_be_bytes([payload[2], payload[3]]);
        let name = match ptype {
            0x0000 => "Generic negative ack",
            0x0001 => "Vehicle ID request",
            0x0004 => "Vehicle announcement",
            0x0005 => "Routing activation request",
            0x0006 => "Routing activation response",
            0x0007 => "Alive check request",
            0x8001 => "Diagnostic message",
            0x8002 => "Diagnostic ack",
            0x8003 => "Diagnostic nack",
            _ => "message",
        };
        format!("DoIP {name}")
    } else {
        "DoIP (truncated)".to_string()
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Doip,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_message() {
        // version 0x02, inverse 0xFD, payload type 0x8001.
        let r = dissect_doip(None, None, 40000, 13400, &[0x02, 0xFD, 0x80, 0x01]);
        assert_eq!(r.protocol, Protocol::Doip);
        assert_eq!(r.summary, "DoIP Diagnostic message");
    }
}
