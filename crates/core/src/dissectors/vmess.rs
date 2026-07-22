// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a VMess / VLESS (V2Ray proxy protocol) packet.
pub fn dissect_vmess(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 16 {
        format!("VMess/VLESS ({})", super::bytes(payload.len() as u64))
    } else {
        let ver = payload[0];
        if ver == 0 {
            format!("VLESS Proxy Frame ({})", super::bytes(payload.len() as u64))
        } else {
            format!("VMess Proxy Frame ({})", super::bytes(payload.len() as u64))
        }
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Vmess,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vless_frame() {
        let mut payload = vec![0u8; 20];
        payload[0] = 0; // VLESS version 0
        let res = dissect_vmess(None, None, 10086, 10086, &payload);
        assert_eq!(res.protocol, Protocol::Vmess);
        assert!(res.summary.contains("VLESS Proxy Frame"));
    }

    #[test]
    fn test_vmess_short_payload() {
        let payload = vec![0x00, 0x01];
        let res = dissect_vmess(None, None, 10086, 10086, &payload);
        assert_eq!(res.protocol, Protocol::Vmess);
        assert!(res.summary.contains("VMess/VLESS (2 bytes)"));
    }
}
