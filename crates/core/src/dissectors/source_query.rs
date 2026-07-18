// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Structural check for a Source engine query: the connectionless prefix is
/// four 0xFF bytes followed by a request/response header byte. Game servers use
/// varied ports, so it's recognised by this prefix.
pub fn looks_like_source(p: &[u8]) -> bool {
    p.len() >= 5 && p[..4] == [0xFF, 0xFF, 0xFF, 0xFF] && p[4] != 0xFF
}

/// Dissect a Source engine query (A2S) — how game clients and browsers ask a
/// Source/GoldSrc server for its info, players and rules (Valve games and many
/// others).
pub fn dissect_source_query(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let name = match payload.get(4) {
        Some(b'T') => "A2S_INFO request",
        Some(b'I') => "A2S_INFO response",
        Some(b'U') => "A2S_PLAYER request",
        Some(b'D') => "A2S_PLAYER response",
        Some(b'V') => "A2S_RULES request",
        Some(b'E') => "A2S_RULES response",
        Some(b'A') => "challenge",
        // "query" here would render as the self-repeating "Source Query query".
        _ => "message",
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SourceQuery,
        summary: format!("Source Query {name}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_request() {
        let mut p = vec![0xFF, 0xFF, 0xFF, 0xFF, b'T'];
        p.extend_from_slice(b"Source Engine Query\0");
        assert!(looks_like_source(&p));
        let r = dissect_source_query(None, None, 40000, 27015, &p);
        assert_eq!(r.protocol, Protocol::SourceQuery);
        assert_eq!(r.summary, "Source Query A2S_INFO request");
    }
}
