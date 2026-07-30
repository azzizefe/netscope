// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! PRP — the other way of surviving a cut cable (IEC 62439-3).
//!
//! HSR and PRP solve the same problem from opposite ends. HSR wraps a frame in
//! a tag and sends it both ways round one ring. PRP does not touch the frame's
//! head at all: it duplicates the frame onto **two completely separate
//! networks**, LAN A and LAN B, and appends a six-byte trailer so the receiver
//! can discard whichever copy arrives second.
//!
//! That design is why PRP failures are invisible. Losing an entire LAN costs
//! nothing — every frame still arrives over the other one, the application
//! never notices, and the plant runs on a redundancy that is no longer there.
//! The trailer is where that shows: it names which LAN each copy crossed, so a
//! capture with only LAN A traffic is a network that has already lost half its
//! redundancy and is one fault away from stopping.
//!
//! Two things ride on EtherType 0x88FB and this module handles both:
//!
//! * **Supervision frames**, which nodes send periodically to announce
//!   themselves. These are the inventory of who is doubly attached.
//! * **The redundancy control trailer (RCT)**, appended to ordinary frames.
//!   It is a *trailer*, so the frame's EtherType is still the inner protocol's
//!   — the trailer is found from the end, not by dispatch.

use crate::models::Protocol;

use super::DissectedResult;

/// The RCT's suffix, and the EtherType supervision frames are sent on.
pub(crate) const PRP_SUFFIX: u16 = 0x88FB;

/// Length of the PRP-1 redundancy control trailer.
const RCT_LEN: usize = 6;

/// A parsed redundancy control trailer.
pub(crate) struct Rct {
    /// Which of the two networks this copy crossed — 'A' or 'B'.
    pub lan: char,
    pub sequence: u16,
}

/// Find the redundancy control trailer at the end of a frame.
///
/// PRP-1 puts it last, after any padding, and ends it with a fixed suffix —
/// that suffix plus the LAN identifier being exactly 0xA or 0xB is what makes
/// finding it from the end safe.
///
/// PRP-0 is deliberately **not** recognised: its trailer is four bytes with no
/// suffix, may sit anywhere before the padding, and can only be confirmed by
/// checking the LSDU size against a frame length the caller would have to
/// supply. Without the suffix there is no evidence that survives being wrong.
pub(crate) fn redundancy_trailer(frame: &[u8]) -> Option<Rct> {
    let rct = frame.get(frame.len().checked_sub(RCT_LEN)?..)?;
    if u16::from_be_bytes([rct[4], rct[5]]) != PRP_SUFFIX {
        return None;
    }
    let lan = match rct[2] >> 4 {
        0xA => 'A',
        0xB => 'B',
        _ => return None,
    };
    Some(Rct {
        lan,
        sequence: u16::from_be_bytes([rct[0], rct[1]]),
    })
}

/// What a supervision TLV says the sending node is.
fn node_kind(tlv_type: u8) -> Option<&'static str> {
    Some(match tlv_type {
        // 20 and 21 both mark a PRP node; the standard separates them but the
        // distinction is not observable here, so it is not invented.
        20 | 21 => "PRP node",
        23 => "HSR node",
        30 => "RedBox",
        31 => "VDAN",
        _ => return None,
    })
}

/// Format a MAC address from a supervision TLV.
fn mac(b: &[u8]) -> String {
    b.iter()
        .map(|o| format!("{o:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Dissect an HSR/PRP supervision frame (EtherType 0x88FB).
pub fn dissect_supervision(payload: &[u8]) -> DissectedResult {
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Prp,
        summary: describe_supervision(payload),
    }
}

fn describe_supervision(payload: &[u8]) -> String {
    let Some(head) = payload.get(..2) else {
        return "PRP supervision (truncated)".to_string();
    };
    // Path and version share the first word; a version of zero omits the
    // sequence number entirely, which shifts everything after it.
    let version = u16::from_be_bytes([head[0], head[1]]) & 0x0fff;
    let mut offset = if version > 0 { 4 } else { 2 };

    // Walk the TLV list rather than searching for a type byte: a MAC address
    // inside one TLV's value encodes identically to the next TLV's header.
    let mut announced = None;
    while let (Some(&tlv_type), Some(&len)) = (payload.get(offset), payload.get(offset + 1)) {
        if tlv_type == 0 {
            break;
        }
        let value = payload.get(offset + 2..offset + 2 + len as usize);
        if announced.is_none() {
            if let (Some(kind), Some(value)) = (node_kind(tlv_type), value) {
                announced = Some((kind, value.get(..6).map(mac)));
            }
        }
        offset += 2 + len as usize;
    }

    match announced {
        Some((kind, Some(address))) => format!("PRP supervision — {kind} {address}"),
        Some((kind, None)) => format!("PRP supervision — {kind}"),
        None => "PRP supervision".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Append a PRP-1 redundancy control trailer to a frame.
    fn with_trailer(frame: &[u8], lan: u8, sequence: u16) -> Vec<u8> {
        let mut p = frame.to_vec();
        p.extend_from_slice(&sequence.to_be_bytes());
        // LAN identifier in the high nibble, LSDU size in the low twelve bits.
        p.extend_from_slice(&(((lan as u16) << 12) | 0x040).to_be_bytes());
        p.extend_from_slice(&PRP_SUFFIX.to_be_bytes());
        p
    }

    /// Build a supervision frame with one TLV.
    fn supervision(version: u16, tlv_type: u8, value: &[u8]) -> Vec<u8> {
        let mut p = version.to_be_bytes().to_vec();
        if version > 0 {
            p.extend_from_slice(&1u16.to_be_bytes());
        }
        p.push(tlv_type);
        p.push(value.len() as u8);
        p.extend_from_slice(value);
        p.push(0);
        p
    }

    /// The reason this dissector exists: which of the two networks a copy
    /// crossed. A capture showing only one LAN is redundancy that is already
    /// gone, and nothing else in the frame says so.
    #[test]
    fn the_trailer_names_which_lan_the_copy_crossed() {
        let a = redundancy_trailer(&with_trailer(b"payload", 0xA, 42)).unwrap();
        assert_eq!(a.lan, 'A');
        assert_eq!(a.sequence, 42);

        let b = redundancy_trailer(&with_trailer(b"payload", 0xB, 42)).unwrap();
        assert_eq!(b.lan, 'B');
        // Both copies of one frame carry the same sequence number — that is
        // what lets a receiver tell a duplicate from a new frame.
        assert_eq!(b.sequence, a.sequence);
    }

    /// The trailer is found from the end of the frame by its suffix. Anything
    /// without that suffix is not claimed, whatever else it looks like.
    #[test]
    fn the_trailer_is_only_claimed_on_its_suffix() {
        assert!(redundancy_trailer(b"an ordinary frame").is_none());
        assert!(redundancy_trailer(&[]).is_none());
        // Right suffix, but a LAN identifier PRP never uses.
        assert!(redundancy_trailer(&with_trailer(b"x", 0x3, 1)).is_none());
        // Right LAN, wrong suffix.
        let mut wrong = with_trailer(b"x", 0xA, 1);
        let n = wrong.len();
        wrong[n - 1] ^= 0xFF;
        assert!(redundancy_trailer(&wrong).is_none());
    }

    /// Supervision frames are the inventory of which nodes are doubly attached.
    #[test]
    fn a_supervision_frame_names_the_node_that_sent_it() {
        let p = supervision(1, 20, &[0x00, 0x1b, 0x21, 0x0a, 0x0b, 0x0c]);
        let r = dissect_supervision(&p);
        assert_eq!(r.protocol, Protocol::Prp);
        assert_eq!(r.summary, "PRP supervision — PRP node 00:1b:21:0a:0b:0c");
    }

    /// The same frame format carries HSR's supervision, and the TLV type is
    /// the only thing that separates them.
    #[test]
    fn the_node_kinds_are_distinguished() {
        let mac = [0x00, 0x1b, 0x21, 0x0a, 0x0b, 0x0c];
        assert!(describe_supervision(&supervision(1, 23, &mac)).contains("HSR node"));
        assert!(describe_supervision(&supervision(1, 30, &mac)).contains("RedBox"));
        assert!(describe_supervision(&supervision(1, 31, &mac)).contains("VDAN"));
    }

    /// Version zero omits the sequence number, which moves the TLV list two
    /// bytes earlier. Reading it at a fixed offset would find the wrong type.
    #[test]
    fn version_zero_shifts_the_tlv_list() {
        let mac = [0x00, 0x1b, 0x21, 0x0a, 0x0b, 0x0c];
        let summary = describe_supervision(&supervision(0, 20, &mac));
        assert_eq!(summary, "PRP supervision — PRP node 00:1b:21:0a:0b:0c");
    }

    /// The TLV list is walked, not scanned. A MAC address inside a value
    /// encodes exactly like a TLV header, so a scan finds a value as a type.
    #[test]
    fn a_value_that_looks_like_a_header_does_not_confuse_the_walk() {
        // This node's MAC begins with 23 (HSR's TLV type) followed by a
        // plausible length — a scan would report it as an HSR node.
        let p = supervision(1, 20, &[23, 0x06, 0x21, 0x0a, 0x0b, 0x0c]);
        let summary = describe_supervision(&p);
        assert!(summary.contains("PRP node"), "{summary}");
        assert!(!summary.contains("HSR"), "{summary}");
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe_supervision(&[]), "PRP supervision (truncated)");
        assert_eq!(describe_supervision(&[0x00]), "PRP supervision (truncated)");
        assert_eq!(describe_supervision(&[0x00, 0x01]), "PRP supervision");
        // A TLV promising more value than the frame holds.
        assert_eq!(
            describe_supervision(&[0x00, 0x00, 20, 200]),
            "PRP supervision"
        );
        // A node kind with a value too short to hold a MAC address.
        assert_eq!(
            describe_supervision(&supervision(1, 20, &[0x00, 0x1b])),
            "PRP supervision — PRP node"
        );
    }
}
