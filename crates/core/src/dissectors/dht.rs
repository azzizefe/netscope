// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Structural check for a BitTorrent DHT (KRPC) message: a bencoded dictionary
/// that starts with `d1:ad` (query args) or `d1:rd` (response). DHT uses random
/// UDP ports, so it's recognised by content.
pub fn looks_like_dht(p: &[u8]) -> bool {
    p.starts_with(b"d1:ad") || p.starts_with(b"d1:rd") || p.starts_with(b"d1:el")
}

/// Dissect a BitTorrent DHT (KRPC) message — the distributed hash table peers
/// use to find each other without a tracker.
pub fn dissect_dht(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let text = String::from_utf8_lossy(&payload[..payload.len().min(256)]);
    let summary = if payload.starts_with(b"d1:rd") {
        "BitTorrent DHT response".to_string()
    } else if payload.starts_with(b"d1:el") {
        "BitTorrent DHT error".to_string()
    } else {
        // Query: the method follows the "1:q<len>:" marker.
        let method = ["ping", "find_node", "get_peers", "announce_peer"]
            .into_iter()
            .find(|m| text.contains(m))
            .unwrap_or("query");
        format!("BitTorrent DHT {method}")
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Dht,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_peers_query() {
        let msg = b"d1:ad2:id20:aaaaaaaaaaaaaaaaaaaae1:q9:get_peers1:y1:qe";
        assert!(looks_like_dht(msg));
        let r = dissect_dht(None, None, 40000, 6881, msg);
        assert_eq!(r.protocol, Protocol::Dht);
        assert_eq!(r.summary, "BitTorrent DHT get_peers");
    }
}
