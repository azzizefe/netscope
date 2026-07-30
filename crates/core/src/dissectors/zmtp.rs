// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Structural check for a ZMTP 3.x greeting: the signature is 0xFF, eight
/// padding bytes, then 0x7F. ZeroMQ uses arbitrary ports, so it's recognised by
/// this greeting.
pub fn looks_like_zmtp(p: &[u8]) -> bool {
    p.len() >= 10 && p[0] == 0xFF && p[9] == 0x7F
}

/// Dissect a ZMTP message — the wire protocol of ZeroMQ, the brokerless
/// messaging library. The greeting also carries the protocol version.
pub fn dissect_zmtp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.get(10) {
        Some(&major) => format!("ZMTP/ZeroMQ greeting (v{major}.x)"),
        None => "ZMTP/ZeroMQ greeting".to_string(),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Zmtp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeting() {
        let mut p = vec![0xFF];
        p.extend_from_slice(&[0u8; 8]);
        p.push(0x7F);
        p.push(0x03); // version major 3
        assert!(looks_like_zmtp(&p));
        let r = dissect_zmtp(None, None, 40000, 5555, &p);
        assert_eq!(r.protocol, Protocol::Zmtp);
        assert_eq!(r.summary, "ZMTP/ZeroMQ greeting (v3.x)");
    }
}
