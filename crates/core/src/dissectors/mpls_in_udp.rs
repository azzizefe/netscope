// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an MPLS-in-UDP (RFC 7510 / UDP port 6635) packet.
pub fn dissect_mpls_in_udp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        format!("MPLS-in-UDP ({})", super::bytes(payload.len() as u64))
    } else {
        let label = (u32::from(payload[0]) << 12) | (u32::from(payload[1]) << 4) | (u32::from(payload[2]) >> 4);
        let bos = (payload[2] & 0x01) != 0;
        let ttl = payload[3];

        format!("MPLS-in-UDP Tunnel — Label {label} (BOS {bos}, TTL {ttl})")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::MplsInUdp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mpls_in_udp() {
        // Label = 1000 (0x003E8), BOS = 1, TTL = 64
        let payload = vec![0x00, 0x3E, 0x81, 0x40];
        let res = dissect_mpls_in_udp(None, None, 6635, 6635, &payload);
        assert_eq!(res.protocol, Protocol::MplsInUdp);
        assert!(res.summary.contains("Label 1000"));
        assert!(res.summary.contains("TTL 64"));
    }

    #[test]
    fn test_mpls_in_udp_short_payload() {
        let payload = vec![0x00, 0x01];
        let res = dissect_mpls_in_udp(None, None, 6635, 6635, &payload);
        assert_eq!(res.protocol, Protocol::MplsInUdp);
        assert!(res.summary.contains("MPLS-in-UDP (2 bytes)"));
    }
}
