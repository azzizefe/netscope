// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a SOCKS proxy message (TCP 1080). Byte 0 is the version: 0x04 for
/// SOCKS4, 0x05 for SOCKS5 (RFC 1928).
pub fn dissect_socks(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.first() {
        Some(4) => {
            let cmd = match payload.get(1) {
                Some(1) => "Connect",
                Some(2) => "Bind",
                _ => "request",
            };
            format!("SOCKS4 {cmd}")
        }
        Some(5) => {
            // A greeting is [ver, nmethods, methods…]; a request is
            // [ver, cmd, rsv, atyp, …] where cmd is 1/2/3.
            match payload.get(1) {
                Some(1) => "SOCKS5 Connect".to_string(),
                Some(2) => "SOCKS5 Bind".to_string(),
                Some(3) => "SOCKS5 UDP Associate".to_string(),
                Some(&n) => format!("SOCKS5 greeting ({n} auth methods)"),
                None => "SOCKS5".to_string(),
            }
        }
        _ => format!("SOCKS ({})", super::bytes(payload.len() as u64)),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Socks,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks5_connect() {
        let r = dissect_socks(None, None, 40000, 1080, &[0x05, 0x01, 0x00, 0x01]);
        assert_eq!(r.protocol, Protocol::Socks);
        assert_eq!(r.summary, "SOCKS5 Connect");
    }

    #[test]
    fn socks4_connect() {
        let r = dissect_socks(None, None, 40000, 1080, &[0x04, 0x01, 0x00, 0x50]);
        assert_eq!(r.summary, "SOCKS4 Connect");
    }
}
