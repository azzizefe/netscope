// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Gnutella message (TCP 6346) — a classic decentralised file-sharing
/// network. A connection opens with a "GNUTELLA CONNECT/0.6" handshake.
pub fn dissect_gnutella(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"GNUTELLA") {
        let line = super::first_text_line(payload);
        format!("Gnutella handshake — {}", super::truncate(&line, 32))
    } else {
        format!("Gnutella message ({})", super::bytes(payload.len() as u64))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Gnutella,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake() {
        let r = dissect_gnutella(None, None, 40000, 6346, b"GNUTELLA CONNECT/0.6\r\n");
        assert_eq!(r.protocol, Protocol::Gnutella);
        assert!(r.summary.contains("GNUTELLA CONNECT"), "{}", r.summary);
    }
}
