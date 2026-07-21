// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! EtherIP — a whole Ethernet segment tunnelled inside IP (RFC 3378, protocol 97).
//!
//! EtherIP does one thing: it puts a complete Ethernet frame, headers and all,
//! into an IP packet. Two sites end up sharing one broadcast domain as though
//! they were patched into the same switch. OpenBSD's bridging and a number of
//! layer-2 VPNs use it.
//!
//! The header is two bytes — a version nibble and twelve reserved bits — which
//! is as thin as encapsulation gets. What matters is what that thinness hides:
//! everything inside is a full Ethernet frame, so the tunnel carries the remote
//! site's broadcasts, its spanning tree, and its ARP. A broadcast storm at one
//! end crosses to the other, and a capture at the tunnel endpoint shows only
//! "IP protocol 97" unless the frame inside is unwrapped.
//!
//! So the tunnel is context and the frame inside is the answer, which is how
//! every other encapsulation here is treated.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Version nibble and twelve reserved bits.
const HEADER_LEN: usize = 2;

/// The only version RFC 3378 defines.
const VERSION: u16 = 3;

/// Dissect an EtherIP tunnel and report the frame inside it.
pub fn dissect_etherip(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    let base = DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Etherip,
        summary: String::new(),
    };

    let Some(head) = payload.get(..HEADER_LEN) else {
        return DissectedResult {
            summary: "EtherIP (truncated)".into(),
            ..base
        };
    };
    let version = u16::from_be_bytes([head[0], head[1]]) >> 12;
    if version != VERSION {
        return DissectedResult {
            summary: format!("EtherIP (version {version})"),
            ..base
        };
    }

    // What is inside is a complete Ethernet frame, so parse that header and
    // dispatch on it — the same shape `dissect_ip_tunnel` uses for IP-in-IP.
    // Each nesting consumes at least a header's worth of bytes, so a tunnel
    // inside a tunnel terminates rather than recursing without bound.
    let inner = super::ethernet::dissect_ethernet(&payload[HEADER_LEN..])
        .map(|eth| super::dispatch_l3(eth.ethertype.0, &eth.payload, 0))
        .filter(|r| !matches!(r.protocol, Protocol::Unknown(_)));

    match inner {
        Some(inner) => DissectedResult {
            summary: format!("EtherIP · {}", inner.summary),
            protocol: inner.protocol,
            ..inner
        },
        None => DissectedResult {
            summary: format!("EtherIP tunnel — {}", super::bytes(payload.len() as u64)),
            ..base
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrap an Ethernet frame in an EtherIP header.
    fn tunnelled(inner: &[u8]) -> Vec<u8> {
        let mut p = (VERSION << 12).to_be_bytes().to_vec();
        p.extend_from_slice(inner);
        p
    }

    /// Build a minimal Ethernet frame carrying an ARP request.
    fn arp_frame() -> Vec<u8> {
        let mut f = vec![0xFF; 6]; // broadcast destination
        f.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        f.extend_from_slice(&[0x08, 0x06]); // EtherType ARP
        f.extend_from_slice(&[
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 10,
            0, 0, 1, 0, 0, 0, 0, 0, 0, 10, 0, 0, 2,
        ]);
        f
    }

    /// The reason this dissector exists: a capture at the endpoint shows only
    /// "IP protocol 97" until the frame inside is unwrapped — and what crosses
    /// the tunnel is the remote site's broadcast traffic.
    #[test]
    fn the_frame_inside_the_tunnel_is_dissected() {
        let r = dissect_etherip(None, None, &tunnelled(&arp_frame()));
        assert_eq!(r.protocol, Protocol::Arp);
        assert!(r.summary.starts_with("EtherIP · "), "{}", r.summary);
        assert!(r.summary.contains("10.0.0.2"), "{}", r.summary);
    }

    /// A version other than the one RFC 3378 defines is not unwrapped, because
    /// nothing says the payload would be an Ethernet frame.
    #[test]
    fn another_version_is_not_unwrapped() {
        let mut wrong = tunnelled(&arp_frame());
        wrong[0] = 0x10;
        let r = dissect_etherip(None, None, &wrong);
        assert_eq!(r.protocol, Protocol::Etherip);
        assert!(r.summary.contains("version 1"), "{}", r.summary);
    }

    /// A tunnel carrying something that is not a readable frame still reports
    /// as the tunnel rather than as an empty relabel.
    #[test]
    fn an_unreadable_payload_falls_back_to_the_tunnel() {
        let r = dissect_etherip(None, None, &tunnelled(&[0xFF; 4]));
        assert_eq!(r.protocol, Protocol::Etherip);
        assert!(r.summary.contains("EtherIP tunnel"), "{}", r.summary);
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_etherip(None, None, &[]);
        assert!(r.summary.contains("truncated"), "{}", r.summary);
        let r = dissect_etherip(None, None, &[0x30]);
        assert!(r.summary.contains("truncated"), "{}", r.summary);
        // Header present, nothing inside.
        let r = dissect_etherip(None, None, &tunnelled(&[]));
        assert_eq!(r.protocol, Protocol::Etherip);
    }
}
