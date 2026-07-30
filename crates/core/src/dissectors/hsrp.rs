// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an HSRP message (UDP 1985) — Cisco's take on gateway redundancy
/// (like VRRP). Byte 0 is the version, byte 1 the opcode, byte 2 the state.
pub fn dissect_hsrp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.get(1) {
        Some(&op) => {
            let name = match op {
                0 => "Hello",
                1 => "Coup",
                2 => "Resign",
                3 => "Advertise",
                _ => "message",
            };
            let state = match payload.get(2) {
                Some(0) => " (Initial)",
                Some(2) => " (Learn)",
                Some(4) => " (Listen)",
                Some(8) => " (Speak)",
                Some(16) => " (Standby)",
                Some(32) => " (Active)",
                _ => "",
            };
            format!("HSRP {name}{state}")
        }
        None => "HSRP (truncated)".to_string(),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Hsrp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_active() {
        // version 0, opcode 0 (Hello), state 32 (Active).
        let r = dissect_hsrp(None, None, 1985, 1985, &[0x00, 0x00, 0x20, 0x03]);
        assert_eq!(r.protocol, Protocol::Hsrp);
        assert_eq!(r.summary, "HSRP Hello (Active)");
    }
}
