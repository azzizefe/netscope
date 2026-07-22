// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an obfs4 (Tor obfuscated pluggable transport v4) packet.
pub fn dissect_obfs4(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 32 {
        format!("obfs4 ({})", super::bytes(payload.len() as u64))
    } else {
        format!("obfs4 Obfuscated Stream ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Obfs4,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_obfs4_stream() {
        let payload = vec![0xFF; 64];
        let res = dissect_obfs4(None, None, 443, 443, &payload);
        assert_eq!(res.protocol, Protocol::Obfs4);
        assert!(res.summary.contains("Obfuscated Stream"));
    }

    #[test]
    fn test_obfs4_short_payload() {
        let payload = vec![0x00, 0x01];
        let res = dissect_obfs4(None, None, 443, 443, &payload);
        assert_eq!(res.protocol, Protocol::Obfs4);
        assert!(res.summary.contains("obfs4 (2 bytes)"));
    }
}
