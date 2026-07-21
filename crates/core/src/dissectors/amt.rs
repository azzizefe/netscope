// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! AMT — multicast across networks that will not carry it (RFC 7450, UDP 2268).
//!
//! Most of the internet does not forward multicast. AMT gets it across anyway:
//! a gateway near the receiver finds a relay near the source and tunnels the
//! multicast inside ordinary unicast UDP. This is how IPTV, market data feeds
//! and multicast-based streaming reach networks whose providers never enabled
//! multicast routing.
//!
//! The exchange is a fixed sequence, and where it stops is the diagnosis. A
//! gateway sends Relay Discovery and expects an Advertisement; it then sends a
//! Request and expects a Membership Query carrying a nonce; only then can its
//! Membership Update join a group and Multicast Data start flowing. A capture
//! showing Discovery with no Advertisement is a relay that is unreachable or
//! anycast-routed to nowhere. Requests answered by Queries but no Multicast
//! Data means the join was accepted and the source is not sending — a very
//! different problem, and one that is otherwise indistinguishable from the
//! first without seeing the tunnel itself.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The message type lives in the low nibble of the first byte; the high nibble
/// is the version and is always zero.
const TYPE_MASK: u8 = 0x0F;

fn message_name(kind: u8) -> Option<&'static str> {
    Some(match kind {
        1 => "Relay Discovery",
        2 => "Relay Advertisement",
        3 => "Request",
        4 => "Membership Query",
        5 => "Membership Update",
        6 => "Multicast Data",
        7 => "Teardown",
        _ => return None,
    })
}

/// Dissect an AMT message.
pub fn dissect_amt(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Amt,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    let Some(&first) = payload.first() else {
        return "AMT".to_string();
    };
    let kind = first & TYPE_MASK;
    let Some(name) = message_name(kind) else {
        return format!("AMT (type {kind})");
    };

    // Multicast Data carries a whole IP packet, and what is inside the tunnel
    // is what a reader actually wants — the tunnel is context.
    if kind == 6 {
        let inner = super::dispatch_l3(super::ETHERTYPE_IPV4, payload.get(2..).unwrap_or(&[]), 0);
        if !matches!(inner.protocol, Protocol::Unknown(_)) {
            return format!("AMT tunnel · {}", inner.summary);
        }
    }
    format!("AMT {name}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reason this dissector exists: where the setup sequence stops is the
    /// diagnosis, so each step has to be distinguishable.
    #[test]
    fn every_step_of_the_setup_is_named() {
        for (kind, expected) in [
            (1u8, "Relay Discovery"),
            (2, "Relay Advertisement"),
            (3, "Request"),
            (4, "Membership Query"),
            (5, "Membership Update"),
            (7, "Teardown"),
        ] {
            let r = dissect_amt(None, None, 2268, 2268, &[kind, 0, 0, 0]);
            assert_eq!(r.protocol, Protocol::Amt);
            assert_eq!(r.summary, format!("AMT {expected}"));
        }
    }

    /// The tunnel is context, not the answer — what is inside it is the point,
    /// exactly as for any other encapsulation.
    #[test]
    fn multicast_data_reports_what_is_in_the_tunnel() {
        // A minimal IPv4/UDP packet addressed to a multicast group.
        let mut inner = vec![
            0x45, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 10, 0, 0, 1,
            239, 1, 1, 1,
        ];
        // UDP header: ports, length, checksum.
        inner.extend_from_slice(&[0x30, 0x39, 0x30, 0x39, 0x00, 0x0c, 0x00, 0x00]);
        inner.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

        let mut p = vec![6, 0];
        p.extend_from_slice(&inner);
        let summary = describe(&p);
        assert!(summary.starts_with("AMT tunnel ·"), "{summary}");
    }

    /// A tunnel carrying something unrecognisable still reports as the tunnel
    /// rather than as an empty relabel.
    #[test]
    fn undecodable_tunnel_contents_fall_back_to_the_message_name() {
        assert_eq!(describe(&[6, 0, 0xFF, 0xFF]), "AMT Multicast Data");
    }

    /// The type is the low nibble; the high one is the version. Reading the
    /// whole byte would make every message an unknown type.
    #[test]
    fn the_type_is_read_from_the_low_nibble() {
        // Version 0, Relay Discovery — the ordinary case.
        assert_eq!(describe(&[0x01, 0, 0, 0]), "AMT Relay Discovery");
        // A future version must not change which message this is.
        assert_eq!(describe(&[0x11, 0, 0, 0]), "AMT Relay Discovery");
        // A type the standard does not define keeps its number.
        assert_eq!(describe(&[0x08]), "AMT (type 8)");
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "AMT");
        assert_eq!(describe(&[1]), "AMT Relay Discovery");
        assert_eq!(describe(&[6]), "AMT Multicast Data");
        assert_eq!(describe(&[0x0F]), "AMT (type 15)");
    }
}
