// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// OLSR message types (RFC 3626 §18.5).
fn message_name(t: u8) -> Option<&'static str> {
    Some(match t {
        1 => "HELLO",
        2 => "TC (topology control)",
        3 => "MID (multiple interface)",
        4 => "HNA (host and network association)",
        // The olsrd implementation adds these two, and they are common in the
        // community mesh deployments that make up most OLSR traffic.
        5 => "LQ HELLO",
        6 => "LQ TC",
        _ => return None,
    })
}

/// A packet is a four-byte header followed by one or more messages.
const PACKET_HEADER: usize = 4;
/// Each message header: type, validity time, size, originator, TTL, hop count
/// and sequence number.
const MESSAGE_HEADER: usize = 12;

/// Dissect an OLSR packet — Optimised Link State Routing, the protocol that
/// holds together most large community wireless meshes, on UDP 698 (RFC 3626).
///
/// A wireless mesh cannot flood link-state the way a wired network does, because
/// every node hears every broadcast and the medium would saturate. OLSR's trick
/// is multipoint relays: each node picks a small subset of neighbours that can
/// reach everyone two hops away, and only those relay. That is what makes the
/// protocol usable on a mesh of hundreds of rooftop radios.
pub fn dissect_olsr(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary =
        parse(payload).unwrap_or_else(|| format!("OLSR ({})", super::bytes(payload.len() as u64)));
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Olsr,
        summary,
    }
}

fn parse(payload: &[u8]) -> Option<String> {
    let packet_len = u16::from_be_bytes([*payload.first()?, *payload.get(1)?]) as usize;
    // The length covers the header, and a packet with no message in it is not
    // something OLSR sends.
    if packet_len < PACKET_HEADER + MESSAGE_HEADER {
        return None;
    }
    let message = payload.get(PACKET_HEADER..)?;
    let msg_type = *message.first()?;
    let name = message_name(msg_type)?;

    // The originator is the node that first generated this message, which is
    // not the same as the neighbour that relayed it to us.
    let originator = message.get(4..8)?;
    let ttl = *message.get(8)?;
    let hops = *message.get(9)?;
    Some(format!(
        "OLSR {name} — from {}.{}.{}.{}, {hops} hops, TTL {ttl}",
        originator[0], originator[1], originator[2], originator[3]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an OLSR packet carrying one message.
    fn olsr(msg_type: u8, originator: [u8; 4], ttl: u8, hops: u8) -> Vec<u8> {
        let total = PACKET_HEADER + MESSAGE_HEADER;
        let mut p = (total as u16).to_be_bytes().to_vec();
        p.extend_from_slice(&1u16.to_be_bytes()); // packet sequence number
        p.push(msg_type);
        p.push(0x06); // validity time
        p.extend_from_slice(&(MESSAGE_HEADER as u16).to_be_bytes());
        p.extend_from_slice(&originator);
        p.push(ttl);
        p.push(hops);
        p.extend_from_slice(&1u16.to_be_bytes()); // message sequence number
        p
    }

    #[test]
    fn hello_names_its_originator() {
        let r = dissect_olsr(None, None, 698, 698, &olsr(1, [10, 0, 0, 5], 1, 0));
        assert_eq!(r.protocol, Protocol::Olsr);
        assert_eq!(r.summary, "OLSR HELLO — from 10.0.0.5, 0 hops, TTL 1");
    }

    /// Topology control is what actually distributes the map of the mesh.
    #[test]
    fn topology_control_is_named() {
        let r = dissect_olsr(None, None, 698, 698, &olsr(2, [10, 0, 0, 5], 255, 3));
        assert_eq!(
            r.summary,
            "OLSR TC (topology control) — from 10.0.0.5, 3 hops, TTL 255"
        );
    }

    /// The link-quality variants are what almost every real deployment sends,
    /// so leaving them out would make most captures unreadable.
    #[test]
    fn link_quality_variants_are_named() {
        assert!(
            dissect_olsr(None, None, 1, 698, &olsr(5, [1, 2, 3, 4], 1, 0))
                .summary
                .contains("LQ HELLO")
        );
        assert!(
            dissect_olsr(None, None, 1, 698, &olsr(6, [1, 2, 3, 4], 255, 2))
                .summary
                .contains("LQ TC")
        );
    }

    /// A HELLO never travels: it describes the link to a direct neighbour, so
    /// its TTL is one and its hop count zero. A TC crosses the whole mesh.
    #[test]
    fn hop_count_distinguishes_local_from_flooded() {
        let local = dissect_olsr(None, None, 1, 698, &olsr(1, [10, 0, 0, 5], 1, 0));
        let flooded = dissect_olsr(None, None, 1, 698, &olsr(2, [10, 0, 0, 5], 252, 3));
        assert!(local.summary.contains("0 hops, TTL 1"));
        assert!(flooded.summary.contains("3 hops, TTL 252"));
    }

    #[test]
    fn unknown_message_type_is_not_claimed() {
        let r = dissect_olsr(None, None, 1, 698, &olsr(99, [1, 2, 3, 4], 1, 0));
        assert_eq!(r.summary, "OLSR (16 bytes)");
    }

    /// A length too small to hold a message means this is not OLSR.
    #[test]
    fn implausible_packet_length_is_rejected() {
        let r = dissect_olsr(None, None, 1, 698, &[0x00, 0x04, 0x00, 0x01, 0x01]);
        assert_eq!(r.summary, "OLSR (5 bytes)");
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_olsr(None, None, 1, 698, &[0x00, 0x10]);
        assert_eq!(r.summary, "OLSR (2 bytes)");
    }
}
