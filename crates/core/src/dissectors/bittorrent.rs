// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The fixed BitTorrent peer-handshake preamble: a length byte 19 followed by
/// the string "BitTorrent protocol" (BEP 3).
const HANDSHAKE: &[u8] = b"\x13BitTorrent protocol";

/// Dissect a BitTorrent peer-wire message (TCP, commonly 6881-6889). The
/// handshake is unmistakable; other traffic on the port is peer messaging.
pub fn dissect_bittorrent(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(HANDSHAKE) {
        "BitTorrent handshake".to_string()
    } else {
        format!("BitTorrent peer message ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::BitTorrent,
        summary,
    }
}

/// Structural check for the BitTorrent handshake, so it can be recognised on
/// the dynamic ports peers actually use, not just the well-known range.
pub fn looks_like_bittorrent(payload: &[u8]) -> bool {
    payload.starts_with(HANDSHAKE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake() {
        let mut p = HANDSHAKE.to_vec();
        p.extend_from_slice(&[0u8; 8]); // reserved
        let r = dissect_bittorrent(None, None, 6881, 40000, &p);
        assert_eq!(r.protocol, Protocol::BitTorrent);
        assert_eq!(r.summary, "BitTorrent handshake");
        assert!(looks_like_bittorrent(&p));
    }
}
