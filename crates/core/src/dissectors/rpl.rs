// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! RPL — the routing protocol for networks of small, battery-powered devices
//! (RFC 6550).
//!
//! Sensors on a mesh cannot run OSPF: they wake briefly, send a few bytes and
//! sleep again, and a routing protocol that floods link-state everywhere would
//! flatten their batteries. RPL instead builds a tree towards a root — a
//! "DODAG" — where each node only has to know its own rank and who its parent
//! is. Traffic climbs the tree to the root and descends to its destination.
//!
//! RPL is carried as ICMPv6 type 155, so it is reached from the ICMP dissector
//! rather than by port.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The ICMPv6 type that carries every RPL control message.
pub(crate) const ICMPV6_TYPE: u8 = 155;

/// The secure variants set the high bit of the code (RFC 6550 §6).
const SECURE_FLAG: u8 = 0x80;

/// RPL message codes (RFC 6550 §6).
fn code_name(code: u8) -> Option<&'static str> {
    Some(match code & !SECURE_FLAG {
        0x00 => "DIS (solicit routing information)",
        0x01 => "DIO (advertise routing information)",
        0x02 => "DAO (advertise a destination)",
        0x03 => "DAO-ACK",
        0x0A => "Consistency Check",
        _ => return None,
    })
}

/// The ICMPv6 header sits before the RPL body: type, code and checksum.
const ICMPV6_HEADER: usize = 4;

/// Dissect an RPL control message, given the whole ICMPv6 payload.
pub fn dissect_rpl(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    let result = |summary: String| DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Rpl,
        summary,
    };

    let Some(&code) = payload.get(1) else {
        return result("RPL (truncated)".into());
    };
    let secure = code & SECURE_FLAG != 0;
    let Some(name) = code_name(code) else {
        return result(format!("RPL message code 0x{code:02x}"));
    };
    let prefix = if secure { "RPL secure " } else { "RPL " };

    // A DIO advertises the sender's position in the tree. The rank is the
    // useful number: it says how far from the root this node is, so a node
    // whose rank keeps changing is one that cannot settle on a parent.
    let body = &payload[payload.len().min(ICMPV6_HEADER)..];
    if code & !SECURE_FLAG == 0x01 && body.len() >= 4 {
        let instance = body[0];
        let version = body[1];
        let rank = u16::from_be_bytes([body[2], body[3]]);
        return result(format!(
            "{prefix}{name} — instance {instance}, version {version}, rank {rank}"
        ));
    }
    // A DAO tells the parent which destinations it can reach through this node.
    if code & !SECURE_FLAG == 0x02 && !body.is_empty() {
        return result(format!("{prefix}{name} — instance {}", body[0]));
    }
    result(format!("{prefix}{name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an ICMPv6 payload carrying an RPL message.
    fn rpl(code: u8, body: &[u8]) -> Vec<u8> {
        let mut p = vec![ICMPV6_TYPE, code, 0x00, 0x00];
        p.extend_from_slice(body);
        p
    }

    #[test]
    fn dio_reports_instance_version_and_rank() {
        // instance 1, version 2, rank 256
        let r = dissect_rpl(None, None, &rpl(0x01, &[1, 2, 0x01, 0x00]));
        assert_eq!(r.protocol, Protocol::Rpl);
        assert_eq!(
            r.summary,
            "RPL DIO (advertise routing information) — instance 1, version 2, rank 256"
        );
    }

    #[test]
    fn dis_solicits_information() {
        let r = dissect_rpl(None, None, &rpl(0x00, &[0, 0]));
        assert_eq!(r.summary, "RPL DIS (solicit routing information)");
    }

    #[test]
    fn dao_names_its_instance() {
        let r = dissect_rpl(None, None, &rpl(0x02, &[7, 0, 0, 0]));
        assert_eq!(r.summary, "RPL DAO (advertise a destination) — instance 7");
    }

    /// The secure variants are the same messages with the high bit set; not
    /// masking it would make every one of them unrecognisable.
    #[test]
    fn secure_variants_are_recognised_and_marked() {
        let r = dissect_rpl(None, None, &rpl(0x81, &[1, 2, 0x01, 0x00]));
        assert!(r.summary.starts_with("RPL secure DIO"));
        let r = dissect_rpl(None, None, &rpl(0x83, &[]));
        assert_eq!(r.summary, "RPL secure DAO-ACK");
    }

    #[test]
    fn unknown_code_reports_its_byte() {
        let r = dissect_rpl(None, None, &rpl(0x7E, &[]));
        assert_eq!(r.summary, "RPL message code 0x7e");
    }

    /// A DIO with no body still names itself rather than reading past the end.
    #[test]
    fn truncated_body_falls_back_to_the_name() {
        let r = dissect_rpl(None, None, &rpl(0x01, &[1]));
        assert_eq!(r.summary, "RPL DIO (advertise routing information)");
        let r = dissect_rpl(None, None, &[ICMPV6_TYPE]);
        assert_eq!(r.summary, "RPL (truncated)");
    }
}
