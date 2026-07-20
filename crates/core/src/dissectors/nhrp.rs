// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// NHRP packet types (RFC 2332 §5.2).
fn packet_name(t: u8) -> Option<&'static str> {
    Some(match t {
        1 => "Resolution Request",
        2 => "Resolution Reply",
        3 => "Registration Request",
        4 => "Registration Reply",
        5 => "Purge Request",
        6 => "Purge Reply",
        7 => "Error Indication",
        _ => return None,
    })
}

/// The fixed header (RFC 2332 §5.2.0), before the mandatory part.
const FIXED_HEADER: usize = 20;
/// Version 1 is the only one defined.
const VERSION_1: u8 = 1;

/// Dissect an NHRP message — Next Hop Resolution Protocol, on IP protocol 54
/// (RFC 2332).
///
/// NHRP is the machinery behind DMVPN, which is how most multi-site enterprise
/// VPNs are built. Every branch office holds one tunnel to a hub, but sending
/// branch-to-branch traffic through the hub wastes bandwidth and adds latency.
/// NHRP lets a branch ask the hub for another branch's real public address, so
/// the two can build a tunnel directly between themselves and drop the hub out
/// of the path.
pub fn dissect_nhrp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    let summary =
        parse(payload).unwrap_or_else(|| format!("NHRP ({})", super::bytes(payload.len() as u64)));
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Nhrp,
        summary,
    }
}

fn parse(payload: &[u8]) -> Option<String> {
    if payload.len() < FIXED_HEADER {
        return None;
    }
    // The address family and protocol type identify what is being resolved;
    // checking the version guards against decoding unrelated traffic.
    let version = payload[16];
    if version != VERSION_1 {
        return None;
    }
    let packet_type = payload[17];
    let name = packet_name(packet_type)?;
    let hop_count = payload[6];
    Some(format!("NHRP {name} — {hop_count} hops remaining"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an NHRP fixed header of the given type.
    fn nhrp(packet_type: u8, hop_count: u8) -> Vec<u8> {
        let mut p = vec![0u8; FIXED_HEADER];
        p[0] = 0x00; // address family: IPv4 (0x0001)
        p[1] = 0x01;
        p[2] = 0x08; // protocol type: IPv4 (0x0800)
        p[3] = 0x00;
        p[6] = hop_count;
        p[16] = VERSION_1;
        p[17] = packet_type;
        p
    }

    #[test]
    fn resolution_request_is_named() {
        let r = dissect_nhrp(None, None, &nhrp(1, 255));
        assert_eq!(r.protocol, Protocol::Nhrp);
        assert_eq!(r.summary, "NHRP Resolution Request — 255 hops remaining");
    }

    /// A branch asking for another branch's address, and the answer, are the
    /// two messages that make a direct tunnel happen.
    #[test]
    fn the_shortcut_exchange_is_legible() {
        assert!(dissect_nhrp(None, None, &nhrp(1, 255))
            .summary
            .contains("Resolution Request"));
        assert!(dissect_nhrp(None, None, &nhrp(2, 254))
            .summary
            .contains("Resolution Reply"));
    }

    /// Registration is how a branch tells the hub where it currently is, which
    /// matters because most branches have a dynamic address.
    #[test]
    fn registration_is_named() {
        assert!(dissect_nhrp(None, None, &nhrp(3, 255))
            .summary
            .contains("Registration Request"));
        assert!(dissect_nhrp(None, None, &nhrp(4, 255))
            .summary
            .contains("Registration Reply"));
    }

    /// A purge is how a stale shortcut gets torn down when the far end moves.
    #[test]
    fn purge_and_error_are_named() {
        assert!(dissect_nhrp(None, None, &nhrp(5, 255))
            .summary
            .contains("Purge Request"));
        assert!(dissect_nhrp(None, None, &nhrp(7, 255))
            .summary
            .contains("Error Indication"));
    }

    /// The version guards against decoding whatever else arrives on IP 54.
    #[test]
    fn foreign_version_is_not_claimed() {
        let mut p = nhrp(1, 255);
        p[16] = 9;
        assert_eq!(dissect_nhrp(None, None, &p).summary, "NHRP (20 bytes)");
    }

    #[test]
    fn unknown_packet_type_is_not_claimed() {
        let r = dissect_nhrp(None, None, &nhrp(99, 255));
        assert_eq!(r.summary, "NHRP (20 bytes)");
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_nhrp(None, None, &[0x00, 0x01, 0x08, 0x00]);
        assert_eq!(r.summary, "NHRP (4 bytes)");
    }
}
