// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! DVMRP — the first multicast routing protocol (IGMP type 0x13).
//!
//! DVMRP floods a multicast stream everywhere and then waits to be told to
//! stop. A router with no interested receivers downstream sends a **Prune**
//! back towards the source; when someone does want the stream again it sends a
//! **Graft**. That is the whole design, and it is why DVMRP does not scale —
//! but it is still what runs the MBone's descendants and a good deal of
//! campus and broadcast-plant multicast.
//!
//! Prune and Graft are the reason to read it. A multicast stream that stops
//! arriving has usually been pruned, and the prune names which router decided
//! it had no listeners left. That distinguishes "the source stopped sending"
//! from "a router upstream concluded nobody was watching" — two failures with
//! identical symptoms at the receiver.
//!
//! It rides inside IGMP rather than on its own protocol number, which is why
//! it is easy to miss entirely: the packet looks like IGMP until the type byte
//! is read.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The IGMP type that means this is DVMRP rather than group membership.
pub(crate) const IGMP_TYPE_DVMRP: u8 = 0x13;

/// Version 3 marks itself in two bytes that version 1 leaves as part of a
/// checksum, so the check is exact rather than a guess.
fn is_version_3(payload: &[u8]) -> bool {
    payload.len() >= 8 && payload[6] == 0xFF && payload[7] == 0x03
}

/// What a version 3 message does.
fn code_v3(code: u8) -> Option<&'static str> {
    Some(match code {
        0x1 => "Probe",
        0x2 => "Report",
        0x3 => "Ask Neighbours",
        0x4 => "Neighbours",
        0x5 => "Ask Neighbours 2",
        0x6 => "Neighbours 2",
        0x7 => "Prune — a router downstream has no listeners left",
        0x8 => "Graft — a listener appeared, resume the stream",
        0x9 => "Graft ACK",
        _ => return None,
    })
}

/// What a version 1 message does. The numbering is unrelated to version 3's.
fn code_v1(code: u8) -> Option<&'static str> {
    Some(match code {
        1 => "Response",
        2 => "Request",
        3 => "Non-membership report",
        4 => "Non-membership cancellation",
        _ => return None,
    })
}

/// Dissect a DVMRP message carried inside IGMP.
pub fn dissect_dvmrp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Dvmrp,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    let Some(&code) = payload.get(1) else {
        return "DVMRP".to_string();
    };
    // The two versions number their messages differently, so reading a v1 code
    // from a v3 table turns a Request into a Report.
    let (version, name) = if is_version_3(payload) {
        (3, code_v3(code))
    } else {
        (1, code_v1(code))
    };
    match name {
        Some(what) => format!("DVMRPv{version} {what}"),
        None => format!("DVMRPv{version} (code {code})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a DVMRP message of the given version and code.
    fn message(version: u8, code: u8) -> Vec<u8> {
        let mut p = vec![IGMP_TYPE_DVMRP, code, 0x00, 0x00, 0x00, 0x00];
        if version == 3 {
            p.extend_from_slice(&[0xFF, 0x03]);
        } else {
            p.extend_from_slice(&[0x00, 0x00]);
        }
        p
    }

    /// The reason this dissector exists: a stream that stopped because a
    /// router decided nobody downstream was listening.
    #[test]
    fn a_prune_is_spelled_out() {
        let r = dissect_dvmrp(None, None, &message(3, 0x7));
        assert_eq!(r.protocol, Protocol::Dvmrp);
        assert!(r.summary.contains("no listeners left"), "{}", r.summary);
    }

    /// A graft is the opposite event and reads only one code apart.
    #[test]
    fn a_graft_is_not_a_prune() {
        let graft = describe(&message(3, 0x8));
        assert!(graft.contains("resume the stream"), "{graft}");
        assert!(!graft.contains("no listeners"), "{graft}");
        assert!(describe(&message(3, 0x9)).contains("Graft ACK"));
    }

    /// The two versions number their messages differently, so the version has
    /// to be established before the code is read. Code 2 is Report in version
    /// 3 and Request in version 1.
    #[test]
    fn the_version_decides_which_code_table_applies() {
        assert_eq!(describe(&message(3, 2)), "DVMRPv3 Report");
        assert_eq!(describe(&message(1, 2)), "DVMRPv1 Request");
    }

    /// Version 3 marks itself exactly; anything else is version 1.
    #[test]
    fn version_three_is_detected_on_its_marker_not_guessed() {
        assert!(is_version_3(&message(3, 1)));
        assert!(!is_version_3(&message(1, 1)));
        // One byte of the marker wrong is not version 3.
        let mut nearly = message(3, 1);
        nearly[7] = 0x02;
        assert!(!is_version_3(&nearly));
        // Too short to carry the marker at all.
        assert!(!is_version_3(&[0x13, 0x01]));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "DVMRP");
        assert_eq!(describe(&[0x13]), "DVMRP");
        // Short enough that the version marker is absent, so version 1 applies.
        assert_eq!(describe(&[0x13, 0x01]), "DVMRPv1 Response");
        assert_eq!(describe(&message(3, 0x0E)), "DVMRPv3 (code 14)");
    }
}
