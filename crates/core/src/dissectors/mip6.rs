// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Mobile IPv6 — keeping an address while moving (RFC 6275, IP protocol 135).
//!
//! A mobile node keeps one permanent home address no matter which network it
//! is attached to. When it moves it tells its home agent "I am now reachable
//! at this care-of address", and the home agent tunnels traffic to it there.
//! Proxy Mobile IPv6 does the same thing on the node's behalf, which is how
//! mobile operators hand a subscriber between gateways without the handset
//! knowing.
//!
//! The Binding Acknowledgement is what makes this worth reading. Its status
//! byte is a single number that says whether the registration was accepted and,
//! if not, exactly why — administratively prohibited, not the home agent for
//! this node, duplicate address detection failed, sequence number out of
//! window. Those have completely different causes and identical symptoms: a
//! device that has network but no connectivity, because its traffic is still
//! being tunnelled somewhere it no longer is.
//!
//! Anything below 128 is an acceptance; 128 and above is a refusal. That split
//! is the protocol's own, and it is the fastest read in the whole message.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Payload proto, header length, type, reserved, checksum.
const HEADER_LEN: usize = 6;

/// The first status value that means the registration was refused.
const STATUS_REFUSED: u8 = 128;

const TYPE_BINDING_UPDATE: u8 = 5;
const TYPE_BINDING_ACK: u8 = 6;
const TYPE_BINDING_ERROR: u8 = 7;

fn message_name(kind: u8) -> Option<&'static str> {
    Some(match kind {
        0 => "Binding Refresh Request",
        1 => "Home Test Init",
        2 => "Care-of Test Init",
        3 => "Home Test",
        4 => "Care-of Test",
        TYPE_BINDING_UPDATE => "Binding Update",
        TYPE_BINDING_ACK => "Binding Acknowledgement",
        TYPE_BINDING_ERROR => "Binding Error",
        8 => "Fast Binding Update",
        9 => "Fast Binding Acknowledgement",
        10 => "Fast Neighbour Advertisement",
        11 => "Experimental",
        12 => "Home Agent Switch",
        13 => "Heartbeat",
        14 => "Handover Initiate",
        15 => "Handover Acknowledge",
        16 => "Binding Revocation",
        17 => "Localized Routing Initiation",
        18 => "Localized Routing Acknowledgement",
        _ => return None,
    })
}

/// Why a home agent refused, or on what terms it accepted.
fn status_name(status: u8) -> Option<&'static str> {
    Some(match status {
        0 => "accepted",
        1 => "accepted, prefix discovery necessary",
        2 => "GRE key option not required",
        3 => "GRE tunnelling but TLV header not supported",
        4 => "multiple care-of addresses incomplete",
        5 => "return home without neighbour discovery",
        6 => "accepted but settings mismatch ignored",
        128 => "reason unspecified",
        129 => "administratively prohibited",
        130 => "insufficient resources",
        131 => "home registration not supported",
        132 => "not home subnet",
        133 => "not home agent for this mobile node",
        134 => "duplicate address detection failed",
        135 => "sequence number out of window",
        136 => "expired home nonce index",
        137 => "expired care-of nonce index",
        138 => "expired nonces",
        139 => "registration type change disallowed",
        140 => "mobile router operation not permitted",
        141 => "invalid prefix",
        142 => "not authorised for prefix",
        143 => "mobile network prefix information unavailable",
        145 => "proxy registration not supported by the LMA",
        146 => "proxy registrations from this MAG not allowed",
        147 => "no home address for this NAI",
        148 => "invalid timestamp option",
        _ => return None,
    })
}

/// Dissect a Mobile IPv6 mobility header.
pub fn dissect_mip6(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Mip6,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    let Some(head) = payload.get(..HEADER_LEN) else {
        return "Mobile IPv6".to_string();
    };
    let kind = head[2];
    let Some(name) = message_name(kind) else {
        return format!("Mobile IPv6 (type {kind})");
    };
    let body = &payload[HEADER_LEN..];

    let is_proxy = payload.get(HEADER_LEN..).map_or(false, |b| {
        b.windows(2).any(|w| w[0] == 8 || w[0] == 11 || w[0] == 14) || b.get(2).map_or(false, |&f| f & 0x20 != 0)
    });
    let proto_prefix = if is_proxy { "PMIPv6 Proxy" } else { "Mobile IPv6" };

    match kind {
        // The status byte leads the acknowledgement, and is the whole answer.
        TYPE_BINDING_ACK | TYPE_BINDING_ERROR => {
            let Some(&status) = body.first() else {
                return format!("{proto_prefix} {name}");
            };
            // A status the standard has not assigned keeps its number rather
            // than being mapped to whichever entry happened to be nearest.
            let reason = match status_name(status) {
                Some(text) => text.to_string(),
                None => format!("status {status}"),
            };
            if status >= STATUS_REFUSED {
                format!("{proto_prefix} {name} — refused: {reason}")
            } else {
                format!("{proto_prefix} {name} — {reason}")
            }
        }
        // The lifetime is what a mobile node is asking for; zero is how it
        // deregisters, which is a different event entirely.
        TYPE_BINDING_UPDATE => {
            let Some(lifetime) = body.get(4..6).map(|b| u16::from_be_bytes([b[0], b[1]])) else {
                return format!("{proto_prefix} {name}");
            };
            if lifetime == 0 {
                format!("{proto_prefix} {name} — deregistering")
            } else {
                // The unit is four seconds, not one.
                format!("{proto_prefix} {name} — lifetime {}s", lifetime as u32 * 4)
            }
        }
        _ => format!("{proto_prefix} {name}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a mobility header of the given type.
    fn header(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut p = vec![59, 1, kind, 0, 0x00, 0x00];
        p.extend_from_slice(body);
        p
    }

    /// A Binding Acknowledgement: status, flags, sequence, lifetime.
    fn ack(status: u8) -> Vec<u8> {
        header(TYPE_BINDING_ACK, &[status, 0x00, 0x00, 0x01, 0x00, 0x10])
    }

    /// The reason this dissector exists: the home agent's refusal reason, on a
    /// device that has network but no connectivity.
    #[test]
    fn a_refusal_says_why() {
        let r = dissect_mip6(None, None, &ack(133));
        assert_eq!(r.protocol, Protocol::Mip6);
        assert_eq!(
            r.summary,
            "Mobile IPv6 Binding Acknowledgement — refused: not home agent for this mobile node"
        );
    }

    /// The refusal reasons have different causes and identical symptoms, so
    /// they have to be told apart.
    #[test]
    fn the_refusal_reasons_are_distinguished() {
        assert!(describe(&ack(129)).contains("administratively prohibited"));
        assert!(describe(&ack(134)).contains("duplicate address detection failed"));
        assert!(describe(&ack(135)).contains("sequence number out of window"));
        assert!(describe(&ack(130)).contains("insufficient resources"));
    }

    /// Below 128 the registration succeeded, and must not read as a failure.
    #[test]
    fn an_acceptance_is_not_reported_as_a_refusal() {
        let accepted = describe(&ack(0));
        assert!(accepted.contains("accepted"), "{accepted}");
        assert!(!accepted.contains("refused"), "{accepted}");

        let refused = describe(&ack(128));
        assert!(refused.contains("refused"), "{refused}");
    }

    /// A status outside the standard keeps its number instead of being mapped
    /// to the nearest entry that exists.
    #[test]
    fn an_unassigned_status_keeps_its_number() {
        let summary = describe(&ack(200));
        assert!(summary.contains("status 200"), "{summary}");
        // It is still above the threshold, so it is still a refusal.
        assert!(summary.contains("refused"), "{summary}");
        // 144 is a real gap in the assigned range.
        assert!(describe(&ack(144)).contains("status 144"));
    }

    /// A lifetime of zero deregisters — the opposite of what a Binding Update
    /// normally does, and it reads identically apart from those two bytes.
    #[test]
    fn a_deregistration_is_not_a_registration() {
        let register = header(TYPE_BINDING_UPDATE, &[0, 1, 0, 0, 0x00, 0x96]);
        assert_eq!(
            describe(&register),
            "Mobile IPv6 Binding Update — lifetime 600s"
        );
        let deregister = header(TYPE_BINDING_UPDATE, &[0, 1, 0, 0, 0x00, 0x00]);
        assert_eq!(
            describe(&deregister),
            "Mobile IPv6 Binding Update — deregistering"
        );
    }

    #[test]
    fn the_other_message_types_are_named() {
        assert_eq!(describe(&header(1, &[])), "Mobile IPv6 Home Test Init");
        assert_eq!(describe(&header(13, &[])), "Mobile IPv6 Heartbeat");
        assert_eq!(describe(&header(16, &[])), "Mobile IPv6 Binding Revocation");
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "Mobile IPv6");
        assert_eq!(describe(&[59, 1, 6, 0, 0]), "Mobile IPv6");
        // Acknowledgement whose status byte has not arrived.
        assert_eq!(
            describe(&header(TYPE_BINDING_ACK, &[])),
            "Mobile IPv6 Binding Acknowledgement"
        );
        // Binding Update with no room for the lifetime.
        assert_eq!(
            describe(&header(TYPE_BINDING_UPDATE, &[0, 1])),
            "Mobile IPv6 Binding Update"
        );
        assert_eq!(describe(&header(99, &[])), "Mobile IPv6 (type 99)");
    }
}
