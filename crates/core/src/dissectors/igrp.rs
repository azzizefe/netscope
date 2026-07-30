// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! IGRP — Cisco's pre-EIGRP interior routing protocol (IP protocol 9).
//!
//! IGRP was Cisco's answer to RIP's fifteen-hop ceiling: a distance-vector
//! protocol with a composite metric built from bandwidth and delay rather than
//! a hop count. EIGRP replaced it and Cisco removed IGRP from IOS long ago.
//!
//! That is exactly why it is worth recognising. IGRP on a modern capture is
//! not a routing design — it is a device old enough to predate its own
//! vendor's replacement for it, still participating in routing. It advertises
//! routes with no authentication whatsoever, so anything that can put a packet
//! on the segment can inject one.
//!
//! The three route counts in the header are the useful read: interior, system
//! and exterior. A neighbour that suddenly advertises exterior routes it never
//! sent before is either newly connected to something, or being spoofed.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Version and opcode, edition, autonomous system, three counts, checksum.
const HEADER_LEN: usize = 12;

/// The only version ever deployed.
const VERSION: u8 = 1;

fn opcode_name(opcode: u8) -> Option<&'static str> {
    Some(match opcode {
        1 => "Update",
        2 => "Request",
        _ => return None,
    })
}

/// Whether a payload is IGRP: version 1 and a defined opcode share one byte.
pub(crate) fn looks_like_igrp(payload: &[u8]) -> bool {
    payload
        .first()
        .is_some_and(|&b| b >> 4 == VERSION && opcode_name(b & 0x0F).is_some())
}

/// Dissect an IGRP message.
pub fn dissect_igrp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Igrp,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    // Protocol 9 is assigned to IGRP, but the version/opcode byte is a cheap
    // and exact check, so a packet that is not IGRP is not described as one.
    if !looks_like_igrp(payload) {
        return "IGRP (unrecognised header)".to_string();
    }
    let Some(head) = payload.get(..HEADER_LEN) else {
        return "IGRP".to_string();
    };
    // Version and opcode share a byte: version in the high nibble.
    let version = head[0] >> 4;
    let opcode = head[0] & 0x0F;
    let Some(name) = opcode_name(opcode) else {
        return format!("IGRP (opcode {opcode})");
    };
    if version != VERSION {
        return format!("IGRP {name} (version {version})");
    }

    let autonomous_system = u16::from_be_bytes([head[2], head[3]]);
    let interior = u16::from_be_bytes([head[4], head[5]]);
    let system = u16::from_be_bytes([head[6], head[7]]);
    let exterior = u16::from_be_bytes([head[8], head[9]]);
    let total = interior as u32 + system as u32 + exterior as u32;

    if total == 0 {
        return format!("IGRP {name} — AS {autonomous_system}");
    }
    // Exterior routes are the ones worth calling out separately: they are how a
    // default route enters, and the least expected thing to see change.
    if exterior > 0 {
        format!("IGRP {name} — AS {autonomous_system}, {total} routes ({exterior} exterior)")
    } else {
        format!("IGRP {name} — AS {autonomous_system}, {total} routes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an IGRP header with the given route counts.
    fn message(opcode: u8, autonomous_system: u16, counts: (u16, u16, u16)) -> Vec<u8> {
        let mut p = vec![(VERSION << 4) | opcode, 1];
        p.extend_from_slice(&autonomous_system.to_be_bytes());
        p.extend_from_slice(&counts.0.to_be_bytes());
        p.extend_from_slice(&counts.1.to_be_bytes());
        p.extend_from_slice(&counts.2.to_be_bytes());
        p.extend_from_slice(&[0x00, 0x00]); // checksum
        p
    }

    /// The reason this dissector exists: unauthenticated routes from a device
    /// old enough to predate its own replacement.
    #[test]
    fn an_update_reports_its_autonomous_system_and_route_counts() {
        let r = dissect_igrp(None, None, &message(1, 100, (5, 2, 0)));
        assert_eq!(r.protocol, Protocol::Igrp);
        assert_eq!(r.summary, "IGRP Update — AS 100, 7 routes");
    }

    /// Exterior routes are how a default route arrives, so they are called out
    /// rather than folded into the total.
    #[test]
    fn exterior_routes_are_called_out() {
        let summary = describe(&message(1, 100, (5, 2, 1)));
        assert!(summary.contains("8 routes"), "{summary}");
        assert!(summary.contains("(1 exterior)"), "{summary}");
    }

    /// A request carries no routes, and must not read as an empty update.
    #[test]
    fn requests_and_updates_are_distinguished() {
        assert_eq!(
            describe(&message(2, 100, (0, 0, 0))),
            "IGRP Request — AS 100"
        );
        assert_eq!(
            describe(&message(1, 100, (0, 0, 0))),
            "IGRP Update — AS 100"
        );
    }

    /// Version and opcode share one byte, so reading the whole byte as an
    /// opcode makes every real packet unrecognisable.
    #[test]
    fn the_version_nibble_is_separated_from_the_opcode() {
        assert!(looks_like_igrp(&message(1, 1, (0, 0, 0))));
        assert!(looks_like_igrp(&message(2, 1, (0, 0, 0))));
        // Version 2 was never deployed, so it is not claimed.
        let mut future = message(1, 1, (0, 0, 0));
        future[0] = (2 << 4) | 1;
        assert!(!looks_like_igrp(&future));
        // A valid version with an opcode the protocol does not define.
        assert!(!looks_like_igrp(&[(VERSION << 4) | 7]));
        assert!(!looks_like_igrp(&[]));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "IGRP (unrecognised header)");
        assert_eq!(describe(&[0x11; 11]), "IGRP");
        assert_eq!(
            describe(&[0x17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            "IGRP (unrecognised header)"
        );
    }
}
