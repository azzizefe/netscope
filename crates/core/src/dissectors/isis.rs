// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! IS-IS — the link-state routing protocol that carries much of the internet's
//! interior routing (ISO/IEC 10589, extended for IP by RFC 1195).
//!
//! IS-IS is unusual among routing protocols in not running over IP at all. It
//! rides directly on the link layer inside an LLC frame, which is part of why
//! it is favoured in large carrier networks: the routing protocol keeps working
//! even when IP addressing is broken or being renumbered underneath it.

use crate::models::Protocol;

use super::DissectedResult;

/// Every IS-IS PDU starts with this discriminator (ISO 10589 §9.1).
const DISCRIMINATOR: u8 = 0x83;
/// The LLC service access point IS-IS uses. This is how an LLC frame is
/// recognised as IS-IS rather than STP or something else.
pub(crate) const LLC_SAP: u8 = 0xFE;

/// The fixed part of the header, before any PDU-specific fields.
const COMMON_HEADER: usize = 8;

/// PDU types (ISO 10589 §9.1, table 3). "Level 1" is routing within an area,
/// "level 2" between areas — the two-level hierarchy that lets IS-IS scale.
fn pdu_name(pdu_type: u8) -> Option<&'static str> {
    Some(match pdu_type {
        15 => "L1 LAN Hello",
        16 => "L2 LAN Hello",
        17 => "Point-to-Point Hello",
        18 => "L1 Link State PDU",
        20 => "L2 Link State PDU",
        24 => "L1 Complete Sequence Numbers",
        25 => "L2 Complete Sequence Numbers",
        26 => "L1 Partial Sequence Numbers",
        27 => "L2 Partial Sequence Numbers",
        _ => return None,
    })
}

/// Whether an LLC payload is an IS-IS PDU.
///
/// The caller has already matched the LLC service access point; this confirms
/// the discriminator so a frame is not decoded as IS-IS on the SAP alone.
pub(crate) fn is_isis(llc_payload: &[u8]) -> bool {
    llc_payload.first() == Some(&DISCRIMINATOR)
}

/// Format a system id — six bytes written as three dot-separated groups, the
/// way every IS-IS implementation displays them.
fn system_id(bytes: &[u8]) -> String {
    bytes
        .chunks(2)
        .map(|c| {
            c.iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .concat()
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Dissect an IS-IS PDU.
pub fn dissect_isis(payload: &[u8]) -> DissectedResult {
    let result = |summary: String| DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Isis,
        summary,
    };

    if payload.len() < COMMON_HEADER {
        return result("IS-IS (truncated header)".into());
    }
    // The PDU type occupies the low five bits; the top three are reserved and
    // would otherwise make every type unrecognisable.
    let pdu_type = payload[4] & 0x1F;
    let Some(name) = pdu_name(pdu_type) else {
        return result(format!("IS-IS PDU type {pdu_type}"));
    };

    // Hellos and sequence-number PDUs both name the system that sent them,
    // but at different offsets, because the hello carries a circuit type and
    // the sequence-number PDU carries a length first.
    let source = match pdu_type {
        15..=17 => payload.get(COMMON_HEADER + 1..COMMON_HEADER + 7),
        24..=27 => payload.get(COMMON_HEADER + 2..COMMON_HEADER + 8),
        _ => None,
    };
    match source {
        Some(id) => result(format!("IS-IS {name} — {}", system_id(id))),
        None => result(format!("IS-IS {name}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an IS-IS PDU header with the given type, followed by `body`.
    fn isis(pdu_type: u8, body: &[u8]) -> Vec<u8> {
        let mut p = vec![
            DISCRIMINATOR,
            27,       // length indicator
            1,        // version / protocol id extension
            0,        // id length (0 means the default of 6)
            pdu_type, // PDU type in the low five bits
            1,        // version
            0,        // reserved
            3,        // maximum area addresses
        ];
        p.extend_from_slice(body);
        p
    }

    #[test]
    fn lan_hello_names_the_sending_system() {
        // Hello body: circuit type, then the six-byte source system id.
        let body = [0x01, 0x19, 0x00, 0x01, 0x00, 0x01, 0x00, 0x07];
        let r = dissect_isis(&isis(15, &body));
        assert_eq!(r.protocol, Protocol::Isis);
        assert_eq!(r.summary, "IS-IS L1 LAN Hello — 1900.0100.0100");
    }

    #[test]
    fn level_two_pdus_are_distinguished() {
        let body = [0u8; 16];
        assert!(dissect_isis(&isis(16, &body))
            .summary
            .contains("L2 LAN Hello"));
        assert!(dissect_isis(&isis(20, &body))
            .summary
            .contains("L2 Link State PDU"));
        assert!(dissect_isis(&isis(18, &body))
            .summary
            .contains("L1 Link State PDU"));
    }

    /// The top three bits of the type byte are reserved; not masking them would
    /// make every PDU from an implementation that sets them unrecognisable.
    #[test]
    fn reserved_bits_are_masked_off_the_pdu_type() {
        let body = [0u8; 16];
        let masked = dissect_isis(&isis(15, &body));
        let with_reserved = dissect_isis(&isis(15 | 0xE0, &body));
        assert_eq!(masked.summary, with_reserved.summary);
    }

    #[test]
    fn sequence_number_pdus_read_their_source_at_the_right_offset() {
        // CSNP body: a two-byte PDU length, then the source id.
        let body = [0x00, 0x21, 0xAB, 0xCD, 0xEF, 0x01, 0x02, 0x03];
        let r = dissect_isis(&isis(24, &body));
        assert_eq!(
            r.summary,
            "IS-IS L1 Complete Sequence Numbers — abcd.ef01.0203"
        );
    }

    #[test]
    fn unknown_pdu_type_reports_its_number() {
        let r = dissect_isis(&isis(9, &[0u8; 8]));
        assert_eq!(r.summary, "IS-IS PDU type 9");
    }

    /// The discriminator is what confirms an LLC frame really is IS-IS.
    #[test]
    fn discriminator_gates_recognition() {
        assert!(is_isis(&[DISCRIMINATOR, 27, 1]));
        assert!(!is_isis(&[0x42, 0x42, 0x03]));
        assert!(!is_isis(&[]));
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_isis(&[DISCRIMINATOR, 27, 1]);
        assert_eq!(r.summary, "IS-IS (truncated header)");
        // A header with no body still names the PDU.
        let r = dissect_isis(&isis(15, &[]));
        assert_eq!(r.summary, "IS-IS L1 LAN Hello");
    }
}
