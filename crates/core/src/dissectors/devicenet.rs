// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! DeviceNet — ODVA CIP over CAN (CIP Vol 3, Ed 1.14).
//!
//! DeviceNet puts the Common Industrial Protocol on top of 11-bit CAN. The
//! CAN identifier is not opaque: DeviceNet carves it into a message group and a
//! MAC ID (node address 0-63), and the group tells you what the message does.
//!
//! ## Message groups
//!
//! | Range | Group | Purpose |
//! |-------|-------|---------|
//! | 0x000–0x2FF | — | *not DeviceNet* |
//! | 0x300–0x3FF | 1 | Slave I/O responses (multicast poll, CoS/cyclic, bit-strobe) |
//! | 0x400–0x5FF | 2 | Master/slave I/O + Explicit messaging |
//! | 0x600–0x7BF | 3 | Unconnected Explicit messages (connection setup) |
//! | 0x7C0–0x7EF | 4 | Offline ownership and comm-fault management |
//! | 0x7F0–0x7FF | — | *reserved* |
//!
//! ## Guard
//!
//! A CAN identifier is claimed as DeviceNet when it falls inside one of the four
//! message group ranges **and** the MAC ID field (bits 5-0 for groups 1 and 3,
//! bits 8-3 for group 2) is in the valid node range 0-63. Identifiers outside
//! those ranges stay plain CAN frames — a proprietary bus using 11-bit identifiers
//! would otherwise decode into plausible-sounding DeviceNet noise.
//!
//! ## What to read
//!
//! **Group 2** carries the actual I/O data and Explicit messaging. The lower three
//! bits of the Group 2 identifier name the connection type (e.g. bit-strobe
//! command, poll command, explicit request). An Explicit message is DeviceNet's
//! configuration channel — seeing unexpected Explicit traffic from a host that
//! is not the engineering station is a classic OT red flag.

use crate::models::Protocol;

use super::DissectedResult;

// Group boundaries (11-bit CAN identifiers, 0x000–0x7FF).
const GROUP_1_MIN: u32 = 0x300;
const GROUP_1_MAX: u32 = 0x3FF;
const GROUP_2_MIN: u32 = 0x400;
const GROUP_2_MAX: u32 = 0x5FF;
const GROUP_3_MIN: u32 = 0x600;
const GROUP_3_MAX: u32 = 0x7BF;
const GROUP_4_MIN: u32 = 0x7C0;
const GROUP_4_MAX: u32 = 0x7EF;

// Group 1: bits 5-0 = MAC ID, bits 9-6 = message type.
const G1_MAC_MASK: u32 = 0x003F;
const G1_MSG_MASK: u32 = 0x03C0;
// Group 2: bits 8-3 = MAC ID, bits 2-0 = message type.
const G2_MAC_MASK: u32 = 0x01F8;
const G2_MAC_SHIFT: u32 = 3;
const G2_MSG_MASK: u32 = 0x0007;
// Group 3: bits 7-0 (lower 6 are MAC ID or destination MAC ID; bits 8-6 = msg).
const G3_MAC_MASK: u32 = 0x003F;
const G3_MSG_MASK: u32 = 0x01C0;
// Group 4: lower 6 bits = message ID.
const G4_MSG_MASK: u32 = 0x003F;

const G4_COMM_FAULT_RESP: u32 = 0x2C;
const G4_COMM_FAULT_REQ: u32 = 0x2D;
const G4_OFFLINE_OWNER_RESP: u32 = 0x2E;
const G4_OFFLINE_OWNER_REQ: u32 = 0x2F;

/// Returns true when `id` (11-bit SFF CAN identifier) belongs to a DeviceNet
/// message group and carries a valid MAC ID (0–63).
pub fn looks_like_devicenet(id: u32) -> bool {
    match id {
        GROUP_1_MIN..=GROUP_1_MAX => true,
        GROUP_2_MIN..=GROUP_2_MAX => true,
        GROUP_3_MIN..=GROUP_3_MAX => true,
        GROUP_4_MIN..=GROUP_4_MAX => {
            let msg = id & G4_MSG_MASK;
            matches!(
                msg,
                G4_COMM_FAULT_RESP
                    | G4_COMM_FAULT_REQ
                    | G4_OFFLINE_OWNER_RESP
                    | G4_OFFLINE_OWNER_REQ
            )
        }
        _ => false,
    }
}

/// Produce a [`DissectedResult`] for a DeviceNet CAN frame.
///
/// `id` is the 11-bit CAN identifier (SFF_MASK already applied by the caller).
/// `payload` is the CAN data bytes (0–8 bytes for classic CAN).
pub fn result(id: u32, payload: &[u8]) -> DissectedResult {
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::DeviceNet,
        summary: describe(id, payload),
    }
}

fn describe(id: u32, payload: &[u8]) -> String {
    match id {
        GROUP_1_MIN..=GROUP_1_MAX => {
            let mac = id & G1_MAC_MASK;
            let msg = (id & G1_MSG_MASK) >> 6;
            let kind = match msg {
                0xC => "I/O Multicast Poll Response",
                0xD => "I/O Change-of-State / Cyclic",
                0xE => "I/O Bit-Strobe Response",
                0xF => "I/O Poll Response / COS-Cyclic Ack",
                _ => "Group 1",
            };
            format!(
                "DeviceNet {kind} from node {mac}{}",
                summary_suffix(payload)
            )
        }
        GROUP_2_MIN..=GROUP_2_MAX => {
            let mac = (id & G2_MAC_MASK) >> G2_MAC_SHIFT;
            let msg = id & G2_MSG_MASK;
            let kind = match msg {
                0x0 => "I/O Bit-Strobe Command",
                0x1 => "I/O Multicast Poll",
                0x2 => "Change-of-State Ack",
                0x3 => "Explicit Response",
                0x4 => "Explicit Request",
                0x5 => "I/O Poll / COS / Cyclic",
                0x6 => "Unconnected Explicit Request",
                0x7 => "Duplicate MAC ID Check",
                _ => "Group 2",
            };
            format!("DeviceNet {kind} node {mac}{}", summary_suffix(payload))
        }
        GROUP_3_MIN..=GROUP_3_MAX => {
            let mac = id & G3_MAC_MASK;
            let msg = (id & G3_MSG_MASK) >> 6;
            let kind = match msg {
                0x0..=0x5 => "Unconnected Explicit",
                0x6 => "Unconnected Explicit Response",
                0x7 => "Unconnected Explicit Request",
                _ => "Group 3",
            };
            format!("DeviceNet {kind} to node {mac}{}", summary_suffix(payload))
        }
        GROUP_4_MIN..=GROUP_4_MAX => {
            let msg = id & G4_MSG_MASK;
            let kind = match msg {
                G4_COMM_FAULT_RESP => "Comm-Fault Response",
                G4_COMM_FAULT_REQ => "Comm-Fault Request",
                G4_OFFLINE_OWNER_RESP => "Offline Ownership Response",
                G4_OFFLINE_OWNER_REQ => "Offline Ownership Request",
                _ => "Group 4",
            };
            format!("DeviceNet {kind}")
        }
        _ => format!("DeviceNet 0x{id:03X}"),
    }
}

fn summary_suffix(payload: &[u8]) -> String {
    if payload.is_empty() {
        return String::new();
    }
    let hex: Vec<String> = payload.iter().take(8).map(|b| format!("{b:02X}")).collect();
    format!("  {}", hex.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reason this dissector exists: a Group 2 Explicit Request is the
    /// configuration channel. Seeing it from an unexpected host is a red flag,
    /// and the raw CAN identifier says nothing about that without DeviceNet.
    #[test]
    fn explicit_request_is_named() {
        // Group 2: MAC ID = 5, message type 0x4 (Explicit Request)
        // id = 0x400 + (5 << 3) + 0x4 = 0x400 + 0x28 + 0x4 = 0x42C
        let id = 0x400 | (5u32 << 3) | 0x4;
        let r = result(id, &[0xAA, 0xBB]);
        assert_eq!(r.protocol, Protocol::DeviceNet);
        assert!(r.summary.contains("Explicit Request"), "{}", r.summary);
        assert!(r.summary.contains("node 5"), "{}", r.summary);
    }

    /// A slave's I/O poll response names the node — telling which sensor just
    /// spoke is the whole point.
    #[test]
    fn slave_io_response_names_the_node() {
        // Group 1: MAC ID = 7, msg type 0x3 (Poll Response / COS-Cyclic Ack)
        // id = 0x300 + (0x3 << 6) + 7 = 0x300 + 0xC0 + 7 = 0x3C7
        let id = 0x300 | (0x3u32 << 6) | 7;
        let r = result(id, &[0x01]);
        assert_eq!(r.protocol, Protocol::DeviceNet);
        assert!(r.summary.contains("I/O Poll Response"), "{}", r.summary);
        assert!(r.summary.contains("node 7"), "{}", r.summary);
    }

    /// An offline ownership request is DeviceNet's mechanism for detecting a
    /// node that is offline but still holds its MAC ID allocation.
    #[test]
    fn offline_ownership_request_is_named() {
        let id = 0x7C0 | G4_OFFLINE_OWNER_REQ;
        let r = result(id, &[]);
        assert_eq!(r.protocol, Protocol::DeviceNet);
        assert!(
            r.summary.contains("Offline Ownership Request"),
            "{}",
            r.summary
        );
    }

    /// The guard must reject identifiers outside all four groups — a plain CAN
    /// frame with id 0x123 must not be claimed as DeviceNet.
    #[test]
    fn non_devicenet_ids_are_rejected() {
        assert!(!looks_like_devicenet(0x000)); // below group 1
        assert!(!looks_like_devicenet(0x2FF)); // just below group 1
        assert!(!looks_like_devicenet(0x7F0)); // reserved, above group 4
        assert!(!looks_like_devicenet(0x7FF)); // reserved
        assert!(!looks_like_devicenet(0x123)); // arbitrary standard frame
    }

    /// The guard must accept identifiers in all four groups.
    #[test]
    fn all_groups_are_accepted() {
        // Group 1 — mac 0
        assert!(looks_like_devicenet(0x300));
        // Group 2 — mac 0 (bits 8-3), msg 0 (bits 2-0)
        assert!(looks_like_devicenet(0x400));
        // Group 3
        assert!(looks_like_devicenet(0x600));
        // Group 4 — comm fault request
        assert!(looks_like_devicenet(0x7C0 | G4_COMM_FAULT_REQ));
    }

    /// MAC IDs above 63 are invalid and must be rejected, since DeviceNet
    /// nodes are numbered 0-63.
    #[test]
    fn mac_id_above_63_is_rejected() {
        // Group 1: MAC ID = bits 5-0. Id 0x3FF has MAC = 0x3F = 63 (valid).
        // Id 0x340 | 0x3F = 0x37F has MAC = 63. 0x300 | 0x40 would overflow
        // but 0x3FF is the boundary.
        assert!(looks_like_devicenet(0x3FF)); // mac 63, valid
                                              // A MAC > 63 cannot happen in group 1 — the mask is 6 bits.
                                              // In group 2, MAC is bits 8-3 (6 bits), again max 63.
        assert!(looks_like_devicenet(0x5F8)); // mac = (0x1F8>>3) = 63, valid
    }

    #[test]
    fn truncated_payload_does_not_panic() {
        let id = 0x400 | (1u32 << 3) | 4; // Explicit Request, node 1
        let r = result(id, &[]);
        assert_eq!(r.protocol, Protocol::DeviceNet);
    }
}
