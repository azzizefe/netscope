// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a HART-IP message (UDP/TCP 5094) — HART process-instrument traffic
/// over IP (industrial field devices). Byte 0 is the version (1); byte 2 is the
/// message id.
pub fn dissect_hartip(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 3 && payload[0] == 1 {
        let name = match payload[2] {
            0 => "Session Initiate",
            1 => "Session Close",
            2 => "Keep-Alive",
            3 => "Token-Passing PDU",
            _ => "message",
        };
        format!("HART-IP {name}")
    } else {
        format!("HART-IP ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Hartip,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_initiate() {
        // version 1, msg type, message id 0 (Session Initiate).
        let r = dissect_hartip(None, None, 40000, 5094, &[0x01, 0x00, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Hartip);
        assert_eq!(r.summary, "HART-IP Session Initiate");
    }
}
