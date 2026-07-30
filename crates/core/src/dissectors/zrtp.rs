// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Structural check for ZRTP: it rides the RTP port but carries the magic
/// cookie "ZRTP" at offset 4 where RTP would have its timestamp.
pub fn looks_like_zrtp(p: &[u8]) -> bool {
    p.len() >= 12 && &p[4..8] == b"ZRTP"
}

/// Dissect a ZRTP message — the key agreement Phil Zimmermann designed for
/// encrypting voice calls. It negotiates SRTP keys in the media stream itself,
/// with no PKI: the two parties read a short authentication string aloud to
/// confirm no one is in the middle.
pub fn dissect_zrtp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    // The message type is an 8-character ASCII block at offset 12.
    let msg = payload
        .get(12..20)
        .map(|b| String::from_utf8_lossy(b).trim().to_string())
        .unwrap_or_default();
    let summary = if msg.is_empty() {
        "ZRTP key agreement".to_string()
    } else {
        format!("ZRTP {}", super::truncate(&msg, 16))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Zrtp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_message() {
        let mut p = vec![0x10, 0x00, 0x00, 0x01];
        p.extend_from_slice(b"ZRTP");
        p.extend_from_slice(&[0u8; 4]); // SSRC
        p.extend_from_slice(b"Hello   ");
        assert!(looks_like_zrtp(&p));
        let r = dissect_zrtp(None, None, 50000, 50001, &p);
        assert_eq!(r.protocol, Protocol::Zrtp);
        assert_eq!(r.summary, "ZRTP Hello");
    }
}
