// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// The TRILL header is six bytes before any options (RFC 6325 §3.2).
const HEADER: usize = 6;
/// Version 0 is the only one defined; it sits in the top two bits.
const VERSION_MASK: u8 = 0xC0;

/// Dissect a TRILL frame — Transparent Interconnection of Lots of Links, which
/// replaces spanning tree with real routing at the Ethernet layer (RFC 6325).
///
/// Spanning tree keeps a switched network loop-free by switching links off,
/// which wastes them. TRILL instead gives each switch a nickname and routes
/// frames between nicknames using IS-IS, so every link carries traffic and the
/// shortest path is actually used. The frame carries a hop count for the same
/// reason IP does: with real routing, a loop would otherwise be fatal.
pub fn dissect_trill(payload: &[u8]) -> DissectedResult {
    let result = |summary: String| DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Trill,
        summary,
    };
    if payload.len() < HEADER {
        return result(format!("TRILL ({})", super::bytes(payload.len() as u64)));
    }
    if payload[0] & VERSION_MASK != 0 {
        return result(format!("TRILL (unexpected version {})", payload[0] >> 6));
    }
    // The multi-destination bit says whether this frame is being flooded to a
    // distribution tree rather than routed to one egress switch.
    let multi_destination = payload[1] & 0x80 != 0;
    // The hop count occupies the low six bits of the second byte.
    let hop_count = payload[1] & 0x3F;
    let egress = u16::from_be_bytes([payload[2], payload[3]]);
    let ingress = u16::from_be_bytes([payload[4], payload[5]]);

    let summary = if multi_destination {
        format!("TRILL multi-destination — from {ingress} via tree {egress}, {hop_count} hops left")
    } else {
        format!("TRILL {ingress} → {egress}, {hop_count} hops left")
    };
    result(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a TRILL header. `op_length` is carried but not otherwise used here.
    fn trill(multi: bool, hop_count: u8, egress: u16, ingress: u16) -> Vec<u8> {
        let mut p = vec![
            0x00, // version 0, reserved 0, op-length high bits 0
            (if multi { 0x80 } else { 0 }) | (hop_count & 0x3F),
        ];
        p.extend_from_slice(&egress.to_be_bytes());
        p.extend_from_slice(&ingress.to_be_bytes());
        p
    }

    #[test]
    fn known_unicast_names_both_nicknames() {
        let r = dissect_trill(&trill(false, 30, 200, 100));
        assert_eq!(r.protocol, Protocol::Trill);
        assert_eq!(r.summary, "TRILL 100 → 200, 30 hops left");
    }

    /// A flooded frame names the distribution tree rather than an egress
    /// switch, so it has to read differently.
    #[test]
    fn multi_destination_names_the_tree() {
        let r = dissect_trill(&trill(true, 25, 5, 100));
        assert_eq!(
            r.summary,
            "TRILL multi-destination — from 100 via tree 5, 25 hops left"
        );
    }

    /// The multi-destination bit shares a byte with the hop count; including it
    /// would report a hop count over a hundred on every flooded frame.
    #[test]
    fn hop_count_excludes_the_multi_destination_bit() {
        let unicast = dissect_trill(&trill(false, 63, 1, 2));
        let flooded = dissect_trill(&trill(true, 63, 1, 2));
        assert!(unicast.summary.contains("63 hops left"));
        assert!(flooded.summary.contains("63 hops left"));
    }

    /// A hop count reaching zero is how TRILL stops a loop.
    #[test]
    fn expiring_frame_is_reported() {
        let r = dissect_trill(&trill(false, 0, 200, 100));
        assert_eq!(r.summary, "TRILL 100 → 200, 0 hops left");
    }

    #[test]
    fn foreign_version_is_not_decoded() {
        let mut p = trill(false, 30, 200, 100);
        p[0] = 0x40; // version 1
        assert_eq!(dissect_trill(&p).summary, "TRILL (unexpected version 1)");
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_trill(&[0x00, 0x1E, 0x00]);
        assert_eq!(r.summary, "TRILL (3 bytes)");
    }
}
