// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// B.A.T.M.A.N. advanced packet types (batman-adv `packet.h`).
fn packet_name(t: u8) -> Option<&'static str> {
    Some(match t {
        0x00 => "IV OGM (originator message)",
        0x01 => "broadcast",
        0x02 => "coded",
        0x03 => "ELP (echo location)",
        0x04 => "OGM2 (originator message v2)",
        0x40 => "unicast",
        0x41 => "unicast fragment",
        0x42 => "unicast 4-address",
        0x43 => "ICMP",
        0x44 => "unicast TVLV",
        _ => return None,
    })
}

/// Every frame starts with a packet type, a compatibility version and a TTL.
const HEADER: usize = 3;

/// Dissect a B.A.T.M.A.N. advanced frame — a mesh routing protocol that works
/// at the Ethernet layer rather than on IP, EtherType 0x4305.
///
/// Most mesh protocols route IP packets. batman-adv instead makes the whole
/// mesh look like one flat Ethernet segment, so anything that works on a LAN —
/// DHCP, mDNS discovery, non-IP protocols — works across the mesh unchanged.
/// The cost is that every node has to be told about every other node, which is
/// what the originator messages are constantly doing.
pub fn dissect_batman(payload: &[u8]) -> DissectedResult {
    let result = |summary: String| DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Batman,
        summary,
    };
    if payload.len() < HEADER {
        return result(format!(
            "batman-adv ({})",
            super::bytes(payload.len() as u64)
        ));
    }
    let packet_type = payload[0];
    let version = payload[1];
    let ttl = payload[2];
    match packet_name(packet_type) {
        Some(name) => result(format!("batman-adv {name} — v{version}, TTL {ttl}")),
        None => result(format!(
            "batman-adv type 0x{packet_type:02x} — v{version}, TTL {ttl}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batman(packet_type: u8, version: u8, ttl: u8) -> Vec<u8> {
        vec![packet_type, version, ttl, 0x00]
    }

    #[test]
    fn originator_message_is_named() {
        let r = dissect_batman(&batman(0x00, 15, 50));
        assert_eq!(r.protocol, Protocol::Batman);
        assert_eq!(
            r.summary,
            "batman-adv IV OGM (originator message) — v15, TTL 50"
        );
    }

    /// The two originator-message generations coexist in real meshes, and which
    /// one a node speaks says which routing algorithm it is running.
    #[test]
    fn both_originator_generations_are_named() {
        assert!(dissect_batman(&batman(0x00, 15, 50))
            .summary
            .contains("IV OGM"));
        assert!(dissect_batman(&batman(0x04, 15, 50))
            .summary
            .contains("OGM2"));
    }

    #[test]
    fn data_carrying_types_are_named() {
        assert!(dissect_batman(&batman(0x40, 15, 50))
            .summary
            .starts_with("batman-adv unicast —"));
        assert!(dissect_batman(&batman(0x01, 15, 50))
            .summary
            .starts_with("batman-adv broadcast —"));
        assert!(dissect_batman(&batman(0x41, 15, 50))
            .summary
            .contains("unicast fragment"));
    }

    /// The compatibility version matters operationally: nodes on different
    /// versions cannot form a mesh, so seeing two is a diagnosis in itself.
    #[test]
    fn compatibility_version_is_reported() {
        assert!(dissect_batman(&batman(0x00, 14, 50))
            .summary
            .contains("v14"));
        assert!(dissect_batman(&batman(0x00, 15, 50))
            .summary
            .contains("v15"));
    }

    #[test]
    fn unknown_type_reports_its_byte() {
        let r = dissect_batman(&batman(0x7E, 15, 50));
        assert_eq!(r.summary, "batman-adv type 0x7e — v15, TTL 50");
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_batman(&[0x00, 0x0F]);
        assert_eq!(r.summary, "batman-adv (2 bytes)");
    }
}
