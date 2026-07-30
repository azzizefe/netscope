// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a NetBIOS Datagram Service message (UDP 138) — the connectionless
/// side of legacy Windows networking (browsing, announcements). Byte 0 is the
/// message type (RFC 1002).
pub fn dissect_nbds(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.first() {
        Some(&t) => {
            let name = match t {
                0x10 => "Direct Unique",
                0x11 => "Direct Group",
                0x12 => "Broadcast",
                0x13 => "Error",
                0x14 => "Query Request",
                0x15 => "Positive Query Response",
                0x16 => "Negative Query Response",
                _ => "datagram",
            };
            format!("NetBIOS-DGM {name}")
        }
        None => "NetBIOS-DGM (empty)".to_string(),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Nbds,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broadcast() {
        let r = dissect_nbds(None, None, 138, 138, &[0x12, 0x00, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Nbds);
        assert_eq!(r.summary, "NetBIOS-DGM Broadcast");
    }
}
