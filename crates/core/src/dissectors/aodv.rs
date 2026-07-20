// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// AODV message types (RFC 3561 §5).
fn message_name(t: u8) -> Option<&'static str> {
    Some(match t {
        1 => "RREQ (route request)",
        2 => "RREP (route reply)",
        3 => "RERR (route error)",
        4 => "RREP-ACK",
        _ => return None,
    })
}

/// A route request is the longest of the four, at 24 bytes.
const RREQ_LEN: usize = 24;
/// A route reply is 20.
const RREP_LEN: usize = 20;

/// Dissect an AODV message — Ad hoc On-Demand Distance Vector routing, on
/// UDP 654 (RFC 3561).
///
/// AODV takes the opposite approach to OLSR: rather than every node
/// continuously maintaining a map of the mesh, it does nothing until someone
/// actually needs to reach somewhere, then floods a route request and keeps the
/// answer only as long as it is used. That suits a network where most nodes
/// talk to almost nobody — at the cost of a delay the first time they do.
pub fn dissect_aodv(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary =
        parse(payload).unwrap_or_else(|| format!("AODV ({})", super::bytes(payload.len() as u64)));
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Aodv,
        summary,
    }
}

fn ipv4(bytes: &[u8]) -> String {
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

fn parse(payload: &[u8]) -> Option<String> {
    let msg_type = *payload.first()?;
    let name = message_name(msg_type)?;
    match msg_type {
        // A route request names who is being looked for and how far the search
        // has already travelled.
        1 if payload.len() >= RREQ_LEN => {
            let hops = payload[3];
            let destination = ipv4(payload.get(8..12)?);
            let originator = ipv4(payload.get(16..20)?);
            Some(format!(
                "AODV {name} — {originator} looking for {destination}, {hops} hops"
            ))
        }
        // A reply names the destination it is answering for.
        2 if payload.len() >= RREP_LEN => {
            let hops = payload[3];
            let destination = ipv4(payload.get(4..8)?);
            let originator = ipv4(payload.get(12..16)?);
            Some(format!(
                "AODV {name} — {destination} reachable, for {originator}, {hops} hops"
            ))
        }
        // An error reports how many destinations just became unreachable, which
        // is the signal that a link in the mesh has died.
        3 if payload.len() >= 8 => {
            let count = payload[3];
            let plural = if count == 1 { "" } else { "s" };
            Some(format!(
                "AODV {name} — {count} destination{plural} unreachable"
            ))
        }
        _ => Some(format!("AODV {name}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a route request looking for `destination` on behalf of `origin`.
    fn rreq(hops: u8, destination: [u8; 4], origin: [u8; 4]) -> Vec<u8> {
        let mut p = vec![1u8, 0x00, 0x00, hops];
        p.extend_from_slice(&1u32.to_be_bytes()); // request id
        p.extend_from_slice(&destination);
        p.extend_from_slice(&0u32.to_be_bytes()); // destination sequence
        p.extend_from_slice(&origin);
        p.extend_from_slice(&1u32.to_be_bytes()); // originator sequence
        p
    }

    /// Build a route reply for `destination`.
    fn rrep(hops: u8, destination: [u8; 4], origin: [u8; 4]) -> Vec<u8> {
        let mut p = vec![2u8, 0x00, 0x00, hops];
        p.extend_from_slice(&destination);
        p.extend_from_slice(&0u32.to_be_bytes()); // destination sequence
        p.extend_from_slice(&origin);
        p.extend_from_slice(&0u32.to_be_bytes()); // lifetime
        p
    }

    #[test]
    fn route_request_names_both_ends() {
        let r = dissect_aodv(None, None, 654, 654, &rreq(2, [10, 0, 0, 9], [10, 0, 0, 1]));
        assert_eq!(r.protocol, Protocol::Aodv);
        assert_eq!(
            r.summary,
            "AODV RREQ (route request) — 10.0.0.1 looking for 10.0.0.9, 2 hops"
        );
    }

    #[test]
    fn route_reply_names_what_became_reachable() {
        let r = dissect_aodv(None, None, 654, 654, &rrep(3, [10, 0, 0, 9], [10, 0, 0, 1]));
        assert_eq!(
            r.summary,
            "AODV RREP (route reply) — 10.0.0.9 reachable, for 10.0.0.1, 3 hops"
        );
    }

    /// A route error is how a broken link propagates through the mesh.
    #[test]
    fn route_error_counts_lost_destinations() {
        let mut p = vec![3u8, 0x00, 0x00, 2];
        p.extend_from_slice(&[0u8; 8]);
        assert_eq!(
            dissect_aodv(None, None, 1, 654, &p).summary,
            "AODV RERR (route error) — 2 destinations unreachable"
        );
        p[3] = 1;
        assert_eq!(
            dissect_aodv(None, None, 1, 654, &p).summary,
            "AODV RERR (route error) — 1 destination unreachable"
        );
    }

    /// A message too short for its own body still names itself rather than
    /// reading past the end.
    #[test]
    fn short_body_falls_back_to_the_name() {
        let r = dissect_aodv(None, None, 1, 654, &[1, 0, 0, 0]);
        assert_eq!(r.summary, "AODV RREQ (route request)");
        let r = dissect_aodv(None, None, 1, 654, &[4, 0, 0, 0]);
        assert_eq!(r.summary, "AODV RREP-ACK");
    }

    #[test]
    fn unknown_type_is_not_claimed() {
        let r = dissect_aodv(None, None, 1, 654, &[9, 0, 0, 0]);
        assert_eq!(r.summary, "AODV (4 bytes)");
    }

    #[test]
    fn empty_input_does_not_panic() {
        let r = dissect_aodv(None, None, 1, 654, &[]);
        assert_eq!(r.summary, "AODV (0 bytes)");
    }
}
