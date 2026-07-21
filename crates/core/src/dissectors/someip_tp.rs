// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! SOME/IP-TP — the segmentation that has no safety net.
//!
//! Plain [`super::someip`] carries a message that fits in one datagram. A
//! camera's object list, a radar's track list, a diagnostic blob being pulled
//! off an ECU — those do not fit, so SOME/IP-TP cuts them into segments and
//! puts an offset on each one.
//!
//! What makes this worth reporting separately is what it deliberately does
//! *not* have. There is no retransmission, no acknowledgement and no negative
//! acknowledgement. Over UDP, a single dropped datagram silently discards the
//! entire message it belonged to — a whole perception frame, an entire
//! diagnostic response — and the receiver's only evidence is a reassembly that
//! never completes. Nothing on the wire says an error occurred.
//!
//! That makes two things worth watching:
//!
//! * **Offsets with a gap between them.** The missing segment is the message
//!   that will never be delivered, and this is the only place it is visible.
//! * **A stream that never shows the last segment.** The more-segments flag is
//!   clear exactly once per message. If it never clears, the message was
//!   truncated in flight and the receiver is still waiting for it.
//!
//! ## The offset counts sixteen-byte units
//!
//! The offset field is 28 bits and the low four bits of that word are flags, so
//! the byte offset is the field **times sixteen**. Reading it as a plain byte
//! count puts every segment at one sixteenth of its real position: the segments
//! overlap, reassembly produces a message of roughly the right length made of
//! the wrong bytes, and nothing reports an error. That is the failure mode this
//! module is most careful about.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The SOME/IP header, before the TP header.
const SOMEIP_HEADER: usize = 16;
/// Offset and flags, in one word.
const TP_HEADER: usize = 4;

/// The bit in the message type that marks a segment.
pub(crate) const TP_FLAG: u8 = 0x20;

/// Name the underlying message, with the segmentation bit removed.
fn base_message(kind: u8) -> &'static str {
    match kind & !TP_FLAG {
        0x00 => "Request",
        0x01 => "Request (no return)",
        0x02 => "Notification",
        0x80 => "Response",
        0x81 => "Error",
        _ => "message",
    }
}

/// Dissect a SOME/IP-TP segment.
pub fn dissect_someip_tp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SomeIpTp,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    let Some(head) = payload.get(..SOMEIP_HEADER + TP_HEADER) else {
        return format!("SOME/IP-TP ({})", super::bytes(payload.len() as u64));
    };
    let service = u16::from_be_bytes([head[0], head[1]]);
    let method = u16::from_be_bytes([head[2], head[3]]);
    let kind = base_message(head[14]);

    let word = u32::from_be_bytes([head[16], head[17], head[18], head[19]]);
    // The offset is the top 28 bits, counted in sixteen-byte units. Reading it
    // as bytes places every segment at a sixteenth of its real position.
    let offset = (word >> 4) * 16;
    let more = word & 0x01 != 0;

    // The last segment is the only one with the flag clear, so it is the only
    // evidence a message arrived whole.
    let position = if more { "more to come" } else { "last segment" };

    format!(
        "SOME/IP-TP {kind} segment — service {service:#06x}, method {method:#06x}, \
offset {offset} ({position})"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a SOME/IP-TP segment.
    fn segment(service: u16, method: u16, kind: u8, units: u32, more: bool) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&service.to_be_bytes());
        v.extend_from_slice(&method.to_be_bytes());
        v.extend_from_slice(&32u32.to_be_bytes()); // length
        v.extend_from_slice(&[0u8; 4]); // request id
        v.push(0x01); // protocol version
        v.push(0x01); // interface version
        v.push(kind | TP_FLAG);
        v.push(0x00); // return code
        let word = (units << 4) | u32::from(more);
        v.extend_from_slice(&word.to_be_bytes());
        v.extend_from_slice(&[0u8; 16]);
        v
    }

    /// The reason this dissector exists: the offsets are the only place a lost
    /// segment — and so a lost message — is visible.
    #[test]
    fn a_segment_reports_its_offset_and_whether_more_follow() {
        let r = dissect_someip_tp(
            None,
            None,
            40000,
            30490,
            &segment(0x1234, 0x0001, 0x80, 2, true),
        );
        assert_eq!(r.protocol, Protocol::SomeIpTp);
        assert_eq!(
            r.summary,
            "SOME/IP-TP Response segment — service 0x1234, method 0x0001, \
offset 32 (more to come)"
        );
    }

    /// The offset counts sixteen-byte units. Read as bytes, every segment lands
    /// at a sixteenth of its position, the segments overlap, and reassembly
    /// produces the wrong bytes at roughly the right length — silently.
    #[test]
    fn the_offset_counts_sixteen_byte_units() {
        assert!(describe(&segment(1, 1, 0x80, 1, true)).contains("offset 16"));
        assert!(describe(&segment(1, 1, 0x80, 2, true)).contains("offset 32"));
        assert!(describe(&segment(1, 1, 0x80, 64, true)).contains("offset 1024"));
        // The naive reading of the same field.
        assert!(!describe(&segment(1, 1, 0x80, 64, true)).contains("offset 64 "));
    }

    /// The flag is clear exactly once per message, so it is the only evidence
    /// the message arrived whole.
    #[test]
    fn the_last_segment_is_distinguished() {
        let last = describe(&segment(1, 1, 0x80, 4, false));
        let middle = describe(&segment(1, 1, 0x80, 4, true));
        assert!(last.contains("last segment"), "{last}");
        assert!(middle.contains("more to come"), "{middle}");
    }

    /// The segmentation bit is not part of the message type. Leaving it in
    /// makes every segmented response an unrecognised message.
    #[test]
    fn the_segmentation_bit_is_removed_from_the_message_type() {
        assert!(describe(&segment(1, 1, 0x00, 0, true)).contains("Request segment"));
        assert!(describe(&segment(1, 1, 0x02, 0, true)).contains("Notification segment"));
        assert!(describe(&segment(1, 1, 0x80, 0, true)).contains("Response segment"));
        assert!(describe(&segment(1, 1, 0x81, 0, true)).contains("Error segment"));
    }

    /// The service and method are what tie a segment to the message it belongs
    /// to; without them a gap cannot be attributed to anything.
    #[test]
    fn the_segment_names_the_message_it_belongs_to() {
        let summary = describe(&segment(0xABCD, 0x0042, 0x80, 0, true));
        assert!(summary.contains("service 0xabcd"), "{summary}");
        assert!(summary.contains("method 0x0042"), "{summary}");
    }

    /// The three reserved bits sit between the offset and the flag, and must
    /// not be read as part of either.
    #[test]
    fn the_reserved_bits_do_not_disturb_the_offset_or_the_flag() {
        let mut with_reserved = segment(1, 1, 0x80, 4, false);
        // Set every reserved bit in the low nibble.
        with_reserved[19] |= 0x0E;
        let summary = describe(&with_reserved);
        assert!(summary.contains("offset 64"), "{summary}");
        assert!(summary.contains("last segment"), "{summary}");
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "SOME/IP-TP (0 bytes)");
        // A full SOME/IP header with no TP header after it.
        assert_eq!(describe(&[0u8; 16]), "SOME/IP-TP (16 bytes)");
        assert_eq!(describe(&[0u8; 19]), "SOME/IP-TP (19 bytes)");
    }
}
