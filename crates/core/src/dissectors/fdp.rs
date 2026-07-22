// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Foundry Discovery Protocol (FDP, UDP 6112 or MAC 01-E0-52-00-00-00) frame.
pub fn dissect_fdp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        let version = payload[0];
        let ttl = payload[1];
        format!("Foundry FDP v{version} (TTL {ttl}s)")
    } else {
        format!("Foundry FDP ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Fdp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fdp_packet() {
        let payload = vec![0x01, 0x78, 0x00, 0x10]; // Version 1, TTL 120s
        let r = dissect_fdp(None, None, 6112, 6112, &payload);
        assert_eq!(r.protocol, Protocol::Fdp);
        assert_eq!(r.summary, "Foundry FDP v1 (TTL 120s)");
    }
}
