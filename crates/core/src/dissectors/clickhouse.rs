// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a ClickHouse native-protocol message (TCP 9000) — the binary
/// protocol its clients use for queries and columnar result blocks. The
/// opening Hello packet carries the client/server name in clear text.
pub fn dissect_clickhouse(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let head = &payload[..payload.len().min(128)];
    let summary = if memchr::memmem::find(head, b"ClickHouse").is_some() {
        "ClickHouse handshake (Hello)".to_string()
    } else {
        // Packet 0 is a client Query; 1 is Data.
        match payload.first() {
            Some(1) => format!("ClickHouse query ({})", super::bytes(payload.len() as u64)),
            Some(2) => format!(
                "ClickHouse data block ({})",
                super::bytes(payload.len() as u64)
            ),
            _ => format!("ClickHouse native ({})", super::bytes(payload.len() as u64)),
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Clickhouse,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello() {
        let r = dissect_clickhouse(None, None, 40000, 9000, b"\x00\x11ClickHouse client");
        assert_eq!(r.protocol, Protocol::Clickhouse);
        assert!(r.summary.contains("handshake"), "{}", r.summary);
    }
}
