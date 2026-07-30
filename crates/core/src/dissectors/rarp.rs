// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a RARP packet (EtherType 0x8035) — the reverse of ARP: a diskless
/// host asking "what's my IP for this MAC?". Same layout as ARP; bytes 6..8 are
/// the operation (3 request, 4 reply).
pub fn dissect_rarp(payload: &[u8]) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let op = u16::from_be_bytes([payload[6], payload[7]]);
        let name = match op {
            3 => "Request",
            4 => "Reply",
            _ => "message",
        };
        format!("RARP {name}")
    } else {
        "RARP (truncated)".to_string()
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Rarp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request() {
        // htype, ptype, hlen, plen, then operation 3 (RARP request).
        let p = [0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x03];
        let r = dissect_rarp(&p);
        assert_eq!(r.protocol, Protocol::Rarp);
        assert_eq!(r.summary, "RARP Request");
    }
}
