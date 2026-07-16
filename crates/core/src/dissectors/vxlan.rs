// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! VXLAN (RFC 7348) — Virtual eXtensible LAN encapsulation, UDP 4789.
//!
//! VXLAN wraps a complete Ethernet frame in UDP so layer-2 segments can span
//! layer-3 networks — the workhorse of Kubernetes/overlay networking (flannel,
//! Cilium), OpenStack and data-centre fabrics. The 8-byte header carries a
//! 24-bit VNI (VXLAN Network Identifier) naming the virtual segment.
//!
//! The inner frame is fed back through the normal Ethernet dissector chain, so
//! the summary tells the whole story: `VXLAN VNI 5000 → DNS Query — a.b`.
//! Outer addressing (the VTEP tunnel endpoints) is kept on the packet — it is
//! what the capture actually shows at every other layer (hex view, flows).

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// IANA-assigned VXLAN port, plus the legacy Linux kernel default.
pub const VXLAN_PORTS: [u16; 2] = [4789, 8472];

// A well-formed VXLAN frame nests at most a handful of times in practice;
// anything deeper is hostile input (fuzzing, crafted pcaps) — stop recursing.
const MAX_NESTING: u8 = 3;

mod depth {
    use std::cell::Cell;
    thread_local! {
        pub(super) static DEPTH: Cell<u8> = const { Cell::new(0) };
    }
}
use depth::DEPTH;

/// Try to dissect a UDP payload as VXLAN. Returns `None` when the header
/// doesn't validate — the caller falls through to its generic UDP summary.
pub fn dissect_vxlan(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<DissectedResult> {
    // 8-byte header + at least an Ethernet header inside.
    if payload.len() < 8 + 14 {
        return None;
    }
    // The I flag (VNI valid) MUST be set; other flag bits are reserved and
    // MUST be zero on transmit (RFC 7348 §5).
    if payload[0] != 0x08 {
        return None;
    }
    let vni = u32::from_be_bytes([0, payload[4], payload[5], payload[6]]);
    let inner = &payload[8..];

    let depth = DEPTH.with(|d| d.get());
    let inner_summary = if depth >= MAX_NESTING {
        format!("{} bytes (nesting too deep to decode)", inner.len())
    } else {
        DEPTH.with(|d| d.set(depth + 1));
        let result = super::dissect(inner);
        DEPTH.with(|d| d.set(depth));
        match (result.src_addr, result.dst_addr) {
            (Some(s), Some(d)) => format!("{} [{s} → {d}]", result.summary),
            _ => result.summary,
        }
    };

    Some(DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Vxlan,
        summary: format!("VXLAN VNI {vni} → {inner_summary}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissectors::test_helpers::{build_dns_query, build_udp_packet};

    /// VXLAN header (flags 0x08, given VNI) + inner frame bytes.
    fn vxlan_payload(vni: u32, inner: &[u8]) -> Vec<u8> {
        let v = vni.to_be_bytes();
        let mut p = vec![0x08, 0, 0, 0, v[1], v[2], v[3], 0];
        p.extend_from_slice(inner);
        p
    }

    #[test]
    fn decodes_inner_dns_query() {
        let inner = build_udp_packet(
            [10, 0, 1, 5],
            [10, 0, 1, 53],
            33000,
            53,
            &build_dns_query("svc.cluster.local", 7),
        );
        let result = dissect_vxlan(
            Some("192.168.0.1".parse().unwrap()),
            Some("192.168.0.2".parse().unwrap()),
            50000,
            4789,
            &vxlan_payload(5000, &inner),
        )
        .unwrap();
        assert_eq!(result.protocol, Protocol::Vxlan);
        // Outer (VTEP) addressing is preserved…
        assert_eq!(result.src_addr.unwrap().to_string(), "192.168.0.1");
        // …and the summary tells the inner story.
        assert!(result.summary.starts_with("VXLAN VNI 5000 → "));
        assert!(result.summary.contains("svc.cluster.local"));
        assert!(result.summary.contains("10.0.1.5 → 10.0.1.53"));
    }

    #[test]
    fn rejects_wrong_flags_and_short_payloads() {
        let inner = build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
        let mut bad_flags = vxlan_payload(1, &inner);
        bad_flags[0] = 0x00; // I flag missing
        assert!(dissect_vxlan(None, None, 1, 4789, &bad_flags).is_none());
        assert!(dissect_vxlan(None, None, 1, 4789, &[0x08; 10]).is_none()); // too short
    }

    #[test]
    fn nested_vxlan_stops_at_depth_limit() {
        // VXLAN in VXLAN in VXLAN in VXLAN … — must not recurse unboundedly.
        let mut frame = build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"innermost");
        for i in 0..6u32 {
            let payload = vxlan_payload(i, &frame);
            frame = build_udp_packet([10, 0, 0, 1], [10, 0, 0, 2], 50000, 4789, &payload);
        }
        let ip_data = &frame[14..];
        let (_s, _d, _p, udp_data) = crate::dissectors::ip::dissect_ipv4(ip_data);
        let result = crate::dissectors::udp::dissect_udp(
            Some("10.0.0.1".parse().unwrap()),
            Some("10.0.0.2".parse().unwrap()),
            &udp_data,
        );
        assert_eq!(result.protocol, Protocol::Vxlan);
        assert!(result.summary.contains("nesting too deep"));
    }
}
