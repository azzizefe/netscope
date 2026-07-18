// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The fixed magic a Bolt client sends before version negotiation.
const MAGIC: [u8; 4] = [0x60, 0x60, 0xB0, 0x17];

/// Dissect a Bolt message (TCP 7687) — the binary protocol Neo4j clients use
/// to run Cypher queries. A connection opens with a magic preamble followed by
/// four candidate protocol versions.
pub fn dissect_bolt(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(&MAGIC) {
        match payload.get(4..8) {
            // Each candidate is 4 bytes; the minor/major pair sits at the end.
            Some(v) => format!("Bolt handshake (offering v{}.{})", v[3], v[2]),
            None => "Bolt handshake".to_string(),
        }
    } else {
        format!("Bolt message ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Bolt,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake() {
        let mut p = MAGIC.to_vec();
        p.extend_from_slice(&[0x00, 0x00, 0x01, 0x05]); // offering 5.1
        let r = dissect_bolt(None, None, 40000, 7687, &p);
        assert_eq!(r.protocol, Protocol::Bolt);
        assert_eq!(r.summary, "Bolt handshake (offering v5.1)");
    }
}
