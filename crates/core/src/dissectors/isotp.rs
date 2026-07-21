// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! ISO-TP — carrying messages longer than a CAN frame (ISO 15765-2).
//!
//! A CAN frame holds eight bytes. Vehicle diagnostics routinely need more, so
//! ISO-TP splits a message across frames: a **First Frame** announcing the
//! total length, then **Consecutive Frames** carrying the rest, with the
//! receiver sending a **Flow Control** frame in between to say whether it can
//! keep up. A message that fits in one frame is a **Single Frame** and needs
//! none of this.
//!
//! This matters because UDS — the diagnostic protocol every garage tool speaks
//! — rides on top of it. Without reading the ISO-TP layer, a diagnostic session
//! on a raw CAN capture is a wall of eight-byte hex lines.
//!
//! ## The frame worth looking for
//!
//! Flow Control carries a status, and two of its three values are the reason a
//! diagnostic session stalls:
//!
//! * **Continue to Send** — normal.
//! * **Wait** — the ECU is asking the tester to hold. A few are ordinary; a
//!   stream of them is an ECU too busy to be diagnosed, and the tool will
//!   eventually time out with a misleading "no response".
//! * **Overflow** — the ECU cannot buffer the message at all, so the transfer
//!   is dead. The tool usually reports this as a communication error rather
//!   than as what it is, which is the ECU refusing on capacity grounds.
//!
//! ## Reassembly
//!
//! Multi-frame messages are assembled, keyed by CAN identifier — a tester and
//! an ECU can have several transfers in flight at once and their frames
//! interleave on the bus, so one shared buffer would splice unrelated messages
//! together. A frame arriving out of sequence means one was lost, and the
//! transfer is abandoned rather than assembled with a hole in it.
//!
//! The state is resettable ([`clear_isotp_reassembler`]) because §1 requires
//! that reading a second capture cannot see the first one's leftovers.

use std::cell::RefCell;
use std::collections::HashMap;

use crate::models::Protocol;

use super::DissectedResult;

/// A message being assembled from a First Frame and the Consecutive Frames
/// after it, keyed by the CAN identifier carrying it.
struct Partial {
    /// How long the First Frame said the whole message would be.
    expected: usize,
    data: Vec<u8>,
    /// The sequence number the next Consecutive Frame must carry.
    next_index: u8,
}

/// No real bus has this many diagnostic transfers open at once; the cap stops a
/// malformed capture growing the map without bound.
const MAX_PENDING: usize = 64;
/// ISO-TP's length field tops out here, so anything longer is malformed.
const MAX_MESSAGE: usize = 4095;

thread_local! {
    static PENDING: RefCell<HashMap<u32, Partial>> = RefCell::new(HashMap::new());
}

/// Discard every partially assembled message.
///
/// This exists for the same reason [`super::tcp::clear_tcp_reassembler`] does:
/// reading a second capture must not see the first one's leftovers. §1's
/// determinism rule is that state is *resettable*, not that there is none, and
/// `a_capture_read_twice_gives_the_same_answers` calls this.
pub fn clear_isotp_reassembler() {
    PENDING.with(|pending| pending.borrow_mut().clear());
}

/// The frame type lives in the high nibble of the first byte.
const TYPE_MASK: u8 = 0xF0;
const LOW_MASK: u8 = 0x0F;

const SINGLE: u8 = 0;
const FIRST: u8 = 1;
const CONSECUTIVE: u8 = 2;
const FLOW_CONTROL: u8 = 3;

/// What the receiver is telling the sender to do.
fn flow_status(status: u8) -> &'static str {
    match status {
        0 => "continue",
        1 => "wait — the ECU is asking the tester to hold",
        2 => "overflow — the ECU cannot buffer this message",
        _ => "reserved status",
    }
}

/// Whether a CAN identifier is one ISO 15765-4 reserves for diagnostics.
///
/// **This is the guard that matters, and the frame shape is not enough on its
/// own.** ISO-TP has no magic: its frame type is a four-bit field, so one CAN
/// payload in four begins with a byte that looks like a valid type. Claiming on
/// shape alone turns a quarter of an arbitrary industrial bus into imaginary
/// diagnostic sessions — which is exactly what
/// `an_unknown_extended_frame_stays_a_can_frame` exists to prevent.
///
/// The identifiers below are reserved by the standard, so traffic on them is
/// diagnostics or it is a bus violating the spec. Everything else stays a plain
/// CAN frame, however much its first byte resembles a frame type.
pub(crate) fn is_diagnostic_id(id: u32, extended: bool) -> bool {
    if extended {
        // 29-bit diagnostic addressing: 0x18DA (physical) and 0x18DB
        // (functional), with the target and source in the low two bytes.
        matches!(id >> 16, 0x18DA | 0x18DB)
    } else {
        // 11-bit: the functional request address and the physical pairs.
        // OBD-II claims these first; ISO-TP sees what it does not.
        id == 0x7DF || (0x7E0..=0x7EF).contains(&id)
    }
}

/// Whether a payload's shape is consistent with ISO-TP, given that the
/// identifier has already said it should be.
pub(crate) fn looks_like_isotp(payload: &[u8]) -> bool {
    let Some(&first) = payload.first() else {
        return false;
    };
    match first >> 4 {
        // A single frame's length must fit the frame and not be zero, except
        // for the CAN FD escape form where the length moves to the next byte.
        SINGLE => match first & LOW_MASK {
            0 => payload.len() > 2,
            n => (n as usize) < payload.len(),
        },
        // A first frame carries a length that would not have fitted in a
        // single frame; anything shorter would have been sent as one.
        FIRST => {
            let len =
                ((first & LOW_MASK) as usize) << 8 | payload.get(1).copied().unwrap_or(0) as usize;
            len > 7
        }
        CONSECUTIVE => payload.len() > 1,
        // Flow control has three defined statuses and two bytes after them.
        FLOW_CONTROL => (first & LOW_MASK) <= 2 && payload.len() >= 3,
        _ => false,
    }
}

/// Dissect an ISO-TP frame carried on `id`, assembling multi-frame messages.
///
/// The identifier is what separates one transfer from another: a tester and an
/// ECU can have several in flight at once and their frames interleave on the
/// bus, so accumulating them into one buffer would splice unrelated messages
/// together.
pub fn dissect_isotp(id: u32, payload: &[u8]) -> DissectedResult {
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::IsoTp,
        summary: assemble(id, payload).unwrap_or_else(|| describe(payload)),
    }
}

/// Feed a frame into the reassembler, returning a summary when this frame is
/// the one that completes a message — or when it is a fragment worth
/// describing in terms of the transfer it belongs to.
///
/// Returns `None` for frames that carry no multi-frame state, leaving them to
/// the stateless [`describe`].
fn assemble(id: u32, payload: &[u8]) -> Option<String> {
    let &first = payload.first()?;
    match first >> 4 {
        FIRST => {
            let expected = ((first & LOW_MASK) as usize) << 8 | *payload.get(1)? as usize;
            if expected > MAX_MESSAGE {
                return None;
            }
            let body = payload.get(2..)?;
            PENDING.with(|pending| {
                let mut pending = pending.borrow_mut();
                // A new First Frame supersedes any transfer already open on
                // this identifier — the standard says the old one is abandoned.
                if pending.len() >= MAX_PENDING && !pending.contains_key(&id) {
                    pending.clear();
                }
                pending.insert(
                    id,
                    Partial {
                        expected,
                        data: body.to_vec(),
                        next_index: 1,
                    },
                );
            });
            Some(format!(
                "ISO-TP first frame — {expected} byte message beginning"
            ))
        }
        CONSECUTIVE => {
            let index = first & LOW_MASK;
            let body = payload.get(1..)?;
            PENDING.with(|pending| {
                let mut pending = pending.borrow_mut();
                let partial = pending.get_mut(&id)?;

                // The index counts 1..15 and wraps to 0. A frame out of order
                // means one was lost, and appending it anyway would assemble a
                // message with a hole in it and hand that to UDS as though it
                // were real — so the transfer is abandoned instead.
                if index != partial.next_index {
                    let expected = partial.next_index;
                    pending.remove(&id);
                    return Some(format!(
                        "ISO-TP consecutive frame #{index} out of order — expected #{expected}, transfer abandoned"
                    ));
                }
                partial.data.extend_from_slice(body);
                partial.next_index = (partial.next_index + 1) % 16;

                if partial.data.len() < partial.expected {
                    let remaining = partial.expected - partial.data.len();
                    return Some(format!(
                        "ISO-TP consecutive frame #{index} — {remaining} bytes still to come"
                    ));
                }

                // Complete. The trailing bytes of the last frame are padding.
                let partial = pending.remove(&id)?;
                let message = &partial.data[..partial.expected];
                Some(match super::uds::describe(message) {
                    Some(uds) => format!("ISO-TP reassembled ({} bytes) · {uds}", partial.expected),
                    None => format!("ISO-TP reassembled — {} byte message", partial.expected),
                })
            })
        }
        _ => None,
    }
}

/// Describe one frame.
///
/// This is the **stateless** view of one frame, used for the types that carry
/// no transfer state and as the fallback when [`assemble`] has nothing to add.
///
/// Only a Single Frame is handed to UDS here. A First Frame carries the opening
/// of a message whose remainder has not arrived, and reading its bytes as a
/// complete UDS request would report a service code with a truncated body —
/// confidently, and wrongly. The reassembler is what turns those into a whole
/// message.
pub(crate) fn describe(payload: &[u8]) -> String {
    let Some(&first) = payload.first() else {
        return "ISO-TP".to_string();
    };

    match (first & TYPE_MASK) >> 4 {
        SINGLE => {
            // The low nibble is the length. Zero means the escape form used by
            // CAN FD, where the real length is in the next byte.
            let (len, body) = match first & LOW_MASK {
                0 => (
                    payload.get(1).copied().unwrap_or(0) as usize,
                    payload.get(2..),
                ),
                n => (n as usize, payload.get(1..)),
            };
            // Only a message that is actually all here goes to UDS. A declared
            // length longer than the frame is a truncated capture, and handing
            // those bytes on would name a service from an incomplete body.
            match body.and_then(|b| b.get(..len)).map(super::uds::describe) {
                Some(Some(uds)) => format!("ISO-TP · {uds}"),
                _ => format!("ISO-TP single frame [{len}]"),
            }
        }
        FIRST => {
            // Twelve bits of length across the first two bytes.
            let len =
                ((first & LOW_MASK) as usize) << 8 | payload.get(1).copied().unwrap_or(0) as usize;
            format!("ISO-TP first frame — {len} byte message beginning")
        }
        CONSECUTIVE => {
            let index = first & LOW_MASK;
            format!("ISO-TP consecutive frame #{index}")
        }
        FLOW_CONTROL => {
            let status = first & LOW_MASK;
            // Block size and separation time follow, and a separation time the
            // tester cannot meet is its own kind of stall.
            let separation = payload.get(2).copied();
            match (status, separation) {
                (0, Some(st)) if st > 0 => format!(
                    "ISO-TP flow control — {}, {}ms between frames",
                    flow_status(status),
                    st
                ),
                _ => format!("ISO-TP flow control — {}", flow_status(status)),
            }
        }
        other => format!("ISO-TP (frame type {other})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reason this dissector exists: a diagnostic request that fits in one
    /// frame is a complete UDS message, and reads as one.
    #[test]
    fn a_single_frame_is_handed_to_uds() {
        // Single frame, 2 bytes: DiagnosticSessionControl, extended session.
        let r = dissect_isotp(0x7E0, &[0x02, 0x10, 0x03, 0, 0, 0, 0, 0]);
        assert_eq!(r.protocol, Protocol::IsoTp);
        assert!(r.summary.starts_with("ISO-TP · UDS"), "{}", r.summary);
    }

    /// A First Frame is the *opening* of a message. Handing its bytes to UDS
    /// would report a service with a truncated body, confidently and wrongly —
    /// so it says what it actually is instead.
    #[test]
    fn a_first_frame_is_not_reported_as_a_complete_message() {
        // First frame announcing a 4095-byte message, starting with 0x10 0x03
        // — the same bytes the single-frame test hands to UDS.
        let summary = describe(&[0x1F, 0xFF, 0x10, 0x03, 0, 0, 0, 0]);
        assert_eq!(summary, "ISO-TP first frame — 4095 byte message beginning");
        assert!(!summary.contains("UDS"), "{summary}");
    }

    /// The length spans twelve bits across two bytes, not one.
    #[test]
    fn the_first_frame_length_spans_two_bytes() {
        assert!(describe(&[0x10, 0x14, 0x62]).contains("20 byte"));
        assert!(describe(&[0x11, 0x00, 0x62]).contains("256 byte"));
    }

    /// Flow control is where a stalled diagnostic session is explained, and
    /// the three statuses mean very different things.
    #[test]
    fn the_flow_control_statuses_are_distinguished() {
        assert!(describe(&[0x30, 0x00, 0x00]).contains("continue"));
        let wait = describe(&[0x31, 0x00, 0x00]);
        assert!(wait.contains("asking the tester to hold"), "{wait}");
        let overflow = describe(&[0x32, 0x00, 0x00]);
        assert!(overflow.contains("cannot buffer"), "{overflow}");
    }

    /// A separation time is its own kind of throttle and is worth reporting.
    #[test]
    fn a_separation_time_is_reported_when_it_is_not_zero() {
        assert!(describe(&[0x30, 0x00, 0x14]).contains("20ms between frames"));
        // Zero means "as fast as you like", which is not worth saying.
        assert_eq!(
            describe(&[0x30, 0x00, 0x00]),
            "ISO-TP flow control — continue"
        );
    }

    /// Consecutive frames carry an index that wraps, and a gap in it is a lost
    /// frame.
    #[test]
    fn consecutive_frames_report_their_index() {
        assert_eq!(describe(&[0x21, 0xAA]), "ISO-TP consecutive frame #1");
        assert_eq!(describe(&[0x2F, 0xAA]), "ISO-TP consecutive frame #15");
    }

    /// CAN FD's escape form puts the length in the second byte, because a
    /// single frame can now be longer than the nibble can express.
    #[test]
    fn the_can_fd_escape_length_is_read_from_the_second_byte() {
        let mut frame = vec![0x00, 0x0A, 0x10, 0x03];
        frame.extend_from_slice(&[0u8; 8]);
        assert!(describe(&frame).contains("UDS"), "{}", describe(&frame));
    }

    /// The identifier is the real guard. ISO-TP has no magic and its frame
    /// type is four bits, so shape alone would claim a quarter of an arbitrary
    /// bus — only the ranges ISO 15765-4 reserves are considered.
    #[test]
    fn only_reserved_diagnostic_identifiers_are_considered() {
        // 29-bit physical and functional diagnostic addressing.
        assert!(is_diagnostic_id(0x18DA_F110, true));
        assert!(is_diagnostic_id(0x18DB_33F1, true));
        // A proprietary extended identifier is not diagnostics.
        assert!(!is_diagnostic_id(0x18AB_0001, true));
        assert!(!is_diagnostic_id(0x0CF0_0400, true));
        // 11-bit: the functional address and the physical pairs.
        assert!(is_diagnostic_id(0x7DF, false));
        assert!(is_diagnostic_id(0x7E8, false));
        assert!(!is_diagnostic_id(0x123, false));
        // The 29-bit ranges must not be read as 11-bit ones or the reverse.
        assert!(!is_diagnostic_id(0x18DA_F110, false));
        assert!(!is_diagnostic_id(0x7DF, true));
    }

    /// The shape check is the second gate, and it rejects the frames that
    /// could not be what they claim.
    #[test]
    fn the_shape_must_agree_as_well() {
        assert!(looks_like_isotp(&[0x02, 0x10, 0x03]));
        assert!(looks_like_isotp(&[0x30, 0x00, 0x00]));
        // A single frame claiming more than it carries.
        assert!(!looks_like_isotp(&[0x07, 0x10]));
        // A first frame whose length would have fitted in a single frame.
        assert!(!looks_like_isotp(&[0x10, 0x04, 0x62]));
        // A flow status the standard does not define.
        assert!(!looks_like_isotp(&[0x35, 0x00, 0x00]));
        // Types 4-7 are FlexRay's extensions, 8-15 undefined; neither is CAN.
        assert!(!looks_like_isotp(&[0x40]));
        assert!(!looks_like_isotp(&[0xF0]));
        assert!(!looks_like_isotp(&[]));
    }

    /// The reason the reassembler exists: a diagnostic reply too long for one
    /// frame is invisible without it — the pieces read as unrelated hex.
    #[test]
    fn a_multi_frame_message_is_reassembled_and_handed_to_uds() {
        clear_isotp_reassembler();
        // A 10-byte message: first frame carries 6 bytes, one consecutive the
        // remaining 4. 0x10 0x03 is DiagnosticSessionControl, extended session.
        let ff = [0x10, 0x0A, 0x10, 0x03, 0x01, 0x02, 0x03, 0x04];
        assert!(dissect_isotp(0x7E0, &ff)
            .summary
            .contains("10 byte message"));

        let cf = [0x21, 0x05, 0x06, 0x07, 0x08, 0xAA, 0xAA, 0xAA];
        let r = dissect_isotp(0x7E0, &cf);
        assert!(
            r.summary.starts_with("ISO-TP reassembled (10 bytes) · UDS"),
            "{}",
            r.summary
        );
    }

    /// Two transfers can be in flight at once and their frames interleave on
    /// the bus. Keying by identifier is what stops them being spliced together.
    #[test]
    fn interleaved_transfers_are_kept_apart() {
        clear_isotp_reassembler();
        // Two first frames on different identifiers.
        dissect_isotp(0x7E0, &[0x10, 0x0A, 0x10, 0x03, 0x01, 0x02, 0x03, 0x04]);
        dissect_isotp(0x7E1, &[0x10, 0x0A, 0x22, 0xF1, 0x90, 0x00, 0x00, 0x00]);

        // Completing one must not disturb the other.
        let first = dissect_isotp(0x7E0, &[0x21, 0x05, 0x06, 0x07, 0x08]);
        assert!(first.summary.contains("reassembled"), "{}", first.summary);
        let second = dissect_isotp(0x7E1, &[0x21, 0x00, 0x00, 0x00, 0x00]);
        assert!(second.summary.contains("reassembled"), "{}", second.summary);
    }

    /// A lost frame leaves a hole. Appending anyway would assemble a message
    /// that never existed and hand it to UDS as though it were real.
    #[test]
    fn an_out_of_order_frame_abandons_the_transfer_rather_than_inventing_one() {
        clear_isotp_reassembler();
        dissect_isotp(0x7E0, &[0x10, 0x0A, 0x10, 0x03, 0x01, 0x02, 0x03, 0x04]);
        // #2 arrives where #1 was expected: one frame was lost.
        let r = dissect_isotp(0x7E0, &[0x22, 0x05, 0x06, 0x07, 0x08]);
        assert!(r.summary.contains("out of order"), "{}", r.summary);
        assert!(r.summary.contains("abandoned"), "{}", r.summary);
        assert!(!r.summary.contains("reassembled"), "{}", r.summary);
    }

    /// A consecutive frame with no transfer open is a fragment of something
    /// that started before the capture did, not the start of a message.
    #[test]
    fn a_consecutive_frame_without_a_transfer_is_not_invented_into_one() {
        clear_isotp_reassembler();
        let r = dissect_isotp(0x7E0, &[0x21, 0x05, 0x06]);
        assert_eq!(r.summary, "ISO-TP consecutive frame #1");
    }

    /// The state must be resettable, or reading a second capture would see the
    /// first one's leftovers. §1 depends on this.
    #[test]
    fn clearing_discards_partial_transfers() {
        clear_isotp_reassembler();
        dissect_isotp(0x7E0, &[0x10, 0x0A, 0x10, 0x03, 0x01, 0x02, 0x03, 0x04]);
        clear_isotp_reassembler();
        // With the transfer gone, the continuation is just a lone fragment.
        let r = dissect_isotp(0x7E0, &[0x21, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(r.summary, "ISO-TP consecutive frame #1");
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "ISO-TP");
        assert_eq!(
            describe(&[0x10]),
            "ISO-TP first frame — 0 byte message beginning"
        );
        assert_eq!(describe(&[0x30]), "ISO-TP flow control — continue");
        // A single frame claiming more than it carries.
        // A declared length longer than the frame is not handed to UDS.
        assert_eq!(describe(&[0x07, 0x10]), "ISO-TP single frame [7]");
        assert_eq!(describe(&[0x00]), "ISO-TP single frame [0]");
    }
}
