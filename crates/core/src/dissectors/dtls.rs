// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Structural check for a DTLS record: content type 20-23 followed by a DTLS
/// version (0xFEFF for 1.0, 0xFEFD for 1.2). Lets DTLS be recognised on the
/// dynamic ports WebRTC/VPN media actually use (RFC 6347).
pub fn looks_like_dtls(p: &[u8]) -> bool {
    p.len() >= 13 && (20..=23).contains(&p[0]) && p[1] == 0xFE && (p[2] == 0xFF || p[2] == 0xFD)
}

/// Dissect a DTLS record (datagram TLS) — encryption for UDP traffic such as
/// WebRTC media and some VPNs.
pub fn dissect_dtls(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let content = match payload.first() {
        Some(20) => "ChangeCipherSpec",
        Some(21) => "Alert",
        Some(22) => "Handshake",
        Some(23) => "Application Data",
        _ => "record",
    };
    let version = match payload.get(2) {
        Some(0xFF) => "1.0",
        Some(0xFD) => "1.2",
        _ => "?",
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Dtls,
        summary: format!("DTLS {version} {content}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_record() {
        let mut p = vec![22, 0xFE, 0xFD, 0x00, 0x00];
        p.extend_from_slice(&[0u8; 8]);
        assert!(looks_like_dtls(&p));
        let r = dissect_dtls(None, None, 50000, 50001, &p);
        assert_eq!(r.protocol, Protocol::Dtls);
        assert_eq!(r.summary, "DTLS 1.2 Handshake");
    }

    #[test]
    fn rejects_non_dtls() {
        assert!(!looks_like_dtls(&[0x16, 0x03, 0x03, 0x00, 0x00]));
    }
}
