// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! SAE J1939 — what a truck's ECUs say to each other over CAN.
//!
//! A 29-bit CAN identifier is not an opaque number: J1939 divides it into a
//! priority, a parameter group number naming the message, and the address of
//! the ECU that sent it. Without that division a capture is a wall of hex; with
//! it, each frame says which box on the vehicle spoke and what about.
//!
//! The message worth finding is DM1, which is the check-engine light on the
//! wire: it carries the suspect parameter number and failure mode of every
//! currently active fault.
//!
//! # What this deliberately does not claim
//!
//! Every 29-bit identifier can be *divided* into J1939's fields, but that does
//! not make it J1939 — a proprietary bus using extended identifiers would
//! decode into nonsense that looks authoritative. So a frame is only claimed
//! when its parameter group number is one the standard actually defines.
//! Anything else stays a plain CAN frame with its identifier shown as it is.

use crate::models::Protocol;

use super::DissectedResult;

/// The identifier splits into priority, two page bits, the PDU format and
/// specific bytes, and the source address.
const SA_MASK: u32 = 0xFF;
const PS_SHIFT: u32 = 8;
const PF_SHIFT: u32 = 16;
const DP_SHIFT: u32 = 24;
/// Priority occupies bits 26-28. Nothing outside the tests reads it — see [`Id`].
#[cfg(test)]
const PRIORITY_SHIFT: u32 = 26;

/// Below this, the PDU format byte means the message is addressed to one ECU
/// and the next byte is that destination; at or above it, the message is
/// broadcast and the next byte is part of the parameter group number.
const PDU1_LIMIT: u32 = 240;

/// The check-engine message: every currently active fault.
const PGN_DM1: u32 = 65226;

/// Parameter groups from the standard. Restricted to those a capture from a
/// working vehicle is actually full of, since an invented name would be worse
/// than a number.
fn pgn_name(pgn: u32) -> Option<&'static str> {
    Some(match pgn {
        0 => "torque/speed control",
        59392 => "acknowledgement",
        59904 => "request",
        60160 => "transport — data transfer",
        60416 => "transport — connection management",
        60928 => "address claimed",
        61443 => "EEC2 — accelerator pedal and load",
        61444 => "EEC1 — engine speed",
        64932 => "engine temperature 2",
        65226 => "DM1 — active faults",
        65227 => "DM2 — previously active faults",
        65228 => "DM3 — clear previously active faults",
        65230 => "DM5 — diagnostic readiness",
        65132 => "tachograph",
        65217 => "high-resolution vehicle distance",
        65253 => "engine hours",
        65257 => "fuel consumption",
        65262 => "engine temperature 1",
        65263 => "engine fluid level and pressure",
        65265 => "cruise control and vehicle speed",
        65266 => "fuel economy",
        65269 => "ambient conditions",
        65270 => "inlet and exhaust conditions",
        65271 => "vehicle electrical power",
        65272 => "transmission fluids",
        65276 => "dash display",
        _ => return None,
    })
}

/// Standard source addresses. A capture is much easier to follow when the
/// sender is "engine" rather than 0.
fn address_name(address: u8) -> Option<&'static str> {
    Some(match address {
        0 => "engine",
        1 => "engine #2",
        3 => "transmission",
        11 => "brakes",
        17 => "instrument cluster",
        33 => "body controller",
        49 => "cab controller",
        249 => "diagnostic tool",
        250 => "diagnostic tool #2",
        _ => return None,
    })
}

/// A decoded J1939 identifier.
///
/// The priority bits are deliberately not kept: they matter to the bus
/// arbitration hardware, not to a reader working out what was said, and a field
/// nothing reads is a field that rots.
pub(crate) struct Id {
    pub pgn: u32,
    pub source: u8,
    /// Set only for destination-specific messages.
    pub destination: Option<u8>,
}

/// Split a 29-bit identifier into its J1939 fields.
///
/// This always succeeds — any 29-bit number divides. Whether the result *means*
/// anything is decided by [`looks_like_j1939`].
pub(crate) fn decode_id(id: u32) -> Id {
    let data_page = (id >> DP_SHIFT) & 0x03;
    let pdu_format = (id >> PF_SHIFT) & 0xFF;
    let pdu_specific = (id >> PS_SHIFT) & 0xFF;
    let source = (id & SA_MASK) as u8;

    // A PDU format below 240 addresses one ECU, and the following byte is that
    // ECU rather than part of the message number.
    let (pgn, destination) = if pdu_format < PDU1_LIMIT {
        (
            (data_page << 16) | (pdu_format << 8),
            Some(pdu_specific as u8),
        )
    } else {
        ((data_page << 16) | (pdu_format << 8) | pdu_specific, None)
    };

    Id {
        pgn,
        source,
        destination,
    }
}

/// Whether an extended CAN frame is J1939, judged by whether its parameter
/// group is one the standard defines rather than by the shape of the number.
pub(crate) fn looks_like_j1939(id: u32) -> bool {
    pgn_name(decode_id(id).pgn).is_some()
}

/// The fault a DM1 message reports.
///
/// The suspect parameter number is split across three bytes with its top three
/// bits living in the high end of the third, which is why it cannot be read as
/// a plain little-endian integer.
fn active_fault(payload: &[u8]) -> Option<String> {
    // Two bytes of lamp status come first, then the fault itself.
    let f = payload.get(2..6)?;
    let spn = (f[0] as u32) | ((f[1] as u32) << 8) | (((f[2] as u32) >> 5) << 16);
    let fmi = f[2] & 0x1F;
    let count = f[3] & 0x7F;
    if spn == 0 {
        return None;
    }
    Some(format!("SPN {spn} FMI {fmi}, seen {count}×",))
}

/// Whether the malfunction lamp is lit — the check-engine light itself.
fn lamp_is_lit(payload: &[u8]) -> bool {
    // The top two bits of the first byte are the malfunction indicator; 0b11
    // means "not available" rather than lit.
    matches!(payload.first().map(|b| b >> 6), Some(0b01))
}

/// Describe a J1939 frame. `payload` is the CAN data field.
pub(crate) fn describe(id: u32, payload: &[u8]) -> String {
    let decoded = decode_id(id);
    let name = match pgn_name(decoded.pgn) {
        Some(n) => n.to_string(),
        None => format!("PGN {}", decoded.pgn),
    };
    let from = match address_name(decoded.source) {
        Some(n) => n.to_string(),
        None => format!("address {}", decoded.source),
    };

    // A DM1 is the check-engine light, so its fault is the whole point of the
    // message and belongs in the summary rather than behind a byte count.
    if decoded.pgn == PGN_DM1 {
        return match active_fault(payload) {
            Some(fault) if lamp_is_lit(payload) => {
                format!("J1939 DM1 — fault lamp lit, {fault} (from {from})")
            }
            Some(fault) => format!("J1939 DM1 — {fault} (from {from})"),
            None => format!("J1939 DM1 — no active faults (from {from})"),
        };
    }

    match decoded.destination {
        // A destination of 255 is the broadcast address, which says nothing.
        Some(255) | None => format!("J1939 {name} (from {from})"),
        Some(to) => {
            let to = match address_name(to) {
                Some(n) => n.to_string(),
                None => format!("address {to}"),
            };
            format!("J1939 {name} ({from} → {to})")
        }
    }
}

/// Build the result for a J1939 frame lifted out of a CAN capture.
pub(crate) fn result(id: u32, payload: &[u8]) -> DissectedResult {
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::J1939,
        summary: describe(id, payload),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assemble a 29-bit identifier from its parts.
    fn id(priority: u32, pdu_format: u32, pdu_specific: u32, source: u32) -> u32 {
        (priority << PRIORITY_SHIFT)
            | (pdu_format << PF_SHIFT)
            | (pdu_specific << PS_SHIFT)
            | source
    }

    /// A broadcast message's group number takes in both identifier bytes.
    #[test]
    fn a_broadcast_message_is_named_and_attributed() {
        // 0xFEEE = 65262, engine temperature, sent by the engine.
        let frame = id(6, 0xFE, 0xEE, 0);
        assert_eq!(decode_id(frame).pgn, 65262);
        assert_eq!(
            describe(frame, &[0u8; 8]),
            "J1939 engine temperature 1 (from engine)"
        );
    }

    /// A PDU format below 240 means the next byte is a destination, not part
    /// of the message number — getting this wrong renames the message.
    #[test]
    fn an_addressed_message_yields_a_destination_not_a_different_pgn() {
        // 0xEA00 = request, addressed to the engine from a diagnostic tool.
        let frame = id(6, 0xEA, 0x00, 249);
        let decoded = decode_id(frame);
        assert_eq!(decoded.pgn, 59904, "the destination leaked into the PGN");
        assert_eq!(decoded.destination, Some(0));
        assert_eq!(
            describe(frame, &[]),
            "J1939 request (diagnostic tool → engine)"
        );
    }

    /// The broadcast destination says nothing, so it is left out rather than
    /// printed as "address 255".
    #[test]
    fn the_broadcast_destination_is_not_shown() {
        let frame = id(6, 0xEA, 0xFF, 249);
        assert_eq!(describe(frame, &[]), "J1939 request (from diagnostic tool)");
    }

    /// DM1 is the check-engine light. The suspect parameter number straddles
    /// three bytes with its top bits in the high end of the third, so a plain
    /// little-endian read gets it wrong.
    #[test]
    fn dm1_reports_the_active_fault() {
        let frame = id(6, 0xFE, 0xCA, 0);
        // Lamp lit, SPN 100 (oil pressure), FMI 1 (below normal), seen 3 times.
        let payload = [0b0100_0000, 0xFF, 100, 0, 1, 3, 0xFF, 0xFF];
        assert_eq!(
            describe(frame, &payload),
            "J1939 DM1 — fault lamp lit, SPN 100 FMI 1, seen 3× (from engine)"
        );
    }

    /// An SPN above 65535 uses the top three bits of the third byte, which is
    /// the part of the layout most easily got wrong.
    #[test]
    fn dm1_reads_a_high_numbered_spn() {
        let frame = id(6, 0xFE, 0xCA, 0);
        // SPN 157000 = 0x26548: low 0x48, mid 0x65, top 0b010.
        let payload = [0b0100_0000, 0xFF, 0x48, 0x65, (0b010 << 5) | 4, 1, 0, 0];
        let summary = describe(frame, &payload);
        assert!(summary.contains("SPN 157000"), "{summary}");
        assert!(summary.contains("FMI 4"), "{summary}");
    }

    /// A vehicle with nothing wrong sends DM1 with an empty fault, and saying
    /// so is more useful than showing zeroes.
    #[test]
    fn dm1_with_no_fault_says_so() {
        let frame = id(6, 0xFE, 0xCA, 0);
        let payload = [0xFF, 0xFF, 0, 0, 0, 0, 0xFF, 0xFF];
        assert_eq!(
            describe(frame, &payload),
            "J1939 DM1 — no active faults (from engine)"
        );
    }

    /// Only groups the standard defines are claimed. A proprietary bus using
    /// extended identifiers must not be given invented message names.
    #[test]
    fn unknown_parameter_groups_are_not_claimed() {
        assert!(looks_like_j1939(id(6, 0xFE, 0xEE, 0)));
        assert!(looks_like_j1939(id(6, 0xEA, 0x00, 249)));
        // 0xAB00 is not a defined group.
        assert!(!looks_like_j1939(id(6, 0xAB, 0x00, 1)));
        assert!(!looks_like_j1939(0x1FFF_FFFF));
    }

    /// An unrecognised sender is reported by number rather than guessed at.
    #[test]
    fn an_unknown_source_is_reported_by_number() {
        let frame = id(6, 0xFE, 0xEE, 200);
        assert_eq!(
            describe(frame, &[0u8; 8]),
            "J1939 engine temperature 1 (from address 200)"
        );
    }

    #[test]
    fn truncated_dm1_does_not_panic() {
        let frame = id(6, 0xFE, 0xCA, 0);
        assert!(describe(frame, &[0x40]).contains("no active faults"));
        assert!(describe(frame, &[]).contains("DM1"));
    }
}
