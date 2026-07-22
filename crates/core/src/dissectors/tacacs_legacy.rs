// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a legacy TACACS / XTACACS (Port 49 authentication) frame.
pub fn dissect_tacacs_legacy(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 2 {
        format!("Legacy TACACS ({})", super::bytes(payload.len() as u64))
    } else {
        let version = payload[0];
        let ptype = payload[1];
        let ptype_name = match ptype {
            1 => "LOGIN",
            2 => "RESPONSE",
            3 => "CHANGE_PASSWORD",
            _ => "TACACS Packet",
        };
        let ver_name = if version == 0x80 { "XTACACS" } else { "Legacy TACACS" };

        format!("{ver_name} — {ptype_name} (Type {ptype})")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TacacsLegacy,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tacacs_legacy_login() {
        let payload = vec![0x00, 0x01, 0x00, 0x10];
        let res = dissect_tacacs_legacy(None, None, 49, 49, &payload);
        assert_eq!(res.protocol, Protocol::TacacsLegacy);
        assert!(res.summary.contains("LOGIN"));
    }

    #[test]
    fn test_tacacs_legacy_short_payload() {
        let payload = vec![0x00];
        let res = dissect_tacacs_legacy(None, None, 49, 49, &payload);
        assert_eq!(res.protocol, Protocol::TacacsLegacy);
        assert!(res.summary.contains("Legacy TACACS (1 byte)"));
    }
}
