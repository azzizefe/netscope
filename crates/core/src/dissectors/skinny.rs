// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Skinny / SCCP message (TCP 2000) — Cisco's lightweight protocol
/// between IP phones and CallManager. The header is a little-endian length and
/// reserved word, then the message id at offset 8.
pub fn dissect_skinny(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 12 {
        let msg_id = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let name = match msg_id {
            0x0000 => "KeepAlive",
            0x0001 => "Register",
            0x0002 => "IpPort",
            0x0003 => "KeypadButton",
            0x0006 => "OffHook",
            0x0007 => "OnHook",
            0x0081 => "RegisterAck",
            0x0100 => "KeepAliveAck",
            0x0111 => "CallState",
            0x008F => "CallInfo",
            _ => "message",
        };
        format!("Skinny (SCCP) {name}")
    } else {
        format!("Skinny (SCCP) ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Skinny,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register() {
        let mut p = Vec::new();
        p.extend_from_slice(&4u32.to_le_bytes()); // length
        p.extend_from_slice(&0u32.to_le_bytes()); // reserved
        p.extend_from_slice(&1u32.to_le_bytes()); // message id: Register
        let r = dissect_skinny(None, None, 40000, 2000, &p);
        assert_eq!(r.protocol, Protocol::Skinny);
        assert_eq!(r.summary, "Skinny (SCCP) Register");
    }
}
