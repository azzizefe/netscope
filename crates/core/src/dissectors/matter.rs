// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Matter message (UDP 5540) — the cross-vendor smart-home standard
/// (formerly Project CHIP). Byte 0 is the message flags; its low nibble is the
/// message format version and bit 2 (0x04) marks a destination node id.
pub fn dissect_matter(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.first() {
        Some(&flags) => {
            let version = flags >> 4;
            format!("Matter message (format v{version})")
        }
        None => "Matter (empty)".to_string(),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Matter,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message() {
        let r = dissect_matter(None, None, 40000, 5540, &[0x00, 0x01, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Matter);
        assert!(r.summary.contains("format v0"), "{}", r.summary);
    }
}
