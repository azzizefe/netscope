// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Shadowsocks encrypted proxy packet.
pub fn dissect_shadowsocks(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 16 {
        format!("Shadowsocks Proxy ({})", super::bytes(payload.len() as u64))
    } else {
        format!("Shadowsocks Encrypted Payload ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Shadowsocks,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shadowsocks_payload() {
        let payload = vec![0xAB; 32];
        let res = dissect_shadowsocks(None, None, 8388, 8388, &payload);
        assert_eq!(res.protocol, Protocol::Shadowsocks);
        assert!(res.summary.contains("Encrypted Payload"));
    }

    #[test]
    fn test_shadowsocks_short_payload() {
        let payload = vec![0x00, 0x01];
        let res = dissect_shadowsocks(None, None, 8388, 8388, &payload);
        assert_eq!(res.protocol, Protocol::Shadowsocks);
        assert!(res.summary.contains("Shadowsocks Proxy (2 bytes)"));
    }
}
