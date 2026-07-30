// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! 6LoWPAN — IPv6 squeezed into an 802.15.4 radio frame (RFC 4944, RFC 6282).
//!
//! An IPv6 header is 40 bytes. An 802.15.4 frame carries at most 127 bytes in
//! total, and the radio and security headers have already taken a bite out of
//! that. Sending IPv6 unmodified would leave almost no room for the payload, so
//! 6LoWPAN compresses the header — often down to a few bytes by eliding
//! anything derivable from the link-layer addresses — and fragments what still
//! does not fit.
//!
//! This dissector reads the dispatch byte that says which of those
//! transformations was applied, which is what identifies the frame; decoding a
//! compressed header back into a full IPv6 one needs the link-layer context and
//! is not attempted.

use crate::models::Protocol;

use super::DissectedResult;

/// Dispatch patterns (RFC 4944 §5.1 and RFC 6282 §3).
enum Dispatch {
    NotLowpan,
    UncompressedIpv6,
    HeaderCompression1,
    BroadcastHeader,
    IpHeaderCompression,
    Mesh,
    FirstFragment,
    LaterFragment,
}

fn classify(dispatch: u8) -> Dispatch {
    match dispatch {
        // The top two bits being zero means the frame is not 6LoWPAN at all.
        0x00..=0x3F => Dispatch::NotLowpan,
        0x41 => Dispatch::UncompressedIpv6,
        0x42 => Dispatch::HeaderCompression1,
        0x50 => Dispatch::BroadcastHeader,
        0x60..=0x7F => Dispatch::IpHeaderCompression,
        0x80..=0xBF => Dispatch::Mesh,
        0xC0..=0xDF => Dispatch::FirstFragment,
        0xE0..=0xFF => Dispatch::LaterFragment,
        _ => Dispatch::NotLowpan,
    }
}

/// Whether a payload looks like a 6LoWPAN frame.
pub(crate) fn looks_like_sixlowpan(payload: &[u8]) -> bool {
    !payload.is_empty() && !matches!(classify(payload[0]), Dispatch::NotLowpan)
}

/// Dissect a 6LoWPAN frame.
pub fn dissect_sixlowpan(payload: &[u8]) -> DissectedResult {
    let result = |summary: String| DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::SixLowpan,
        summary,
    };
    let Some(&dispatch) = payload.first() else {
        return result("6LoWPAN (empty)".into());
    };

    let summary = match classify(dispatch) {
        Dispatch::NotLowpan => format!("6LoWPAN (not a 6LoWPAN frame, dispatch 0x{dispatch:02x})"),
        Dispatch::UncompressedIpv6 => "6LoWPAN uncompressed IPv6".to_string(),
        Dispatch::HeaderCompression1 => "6LoWPAN HC1 compressed header".to_string(),
        Dispatch::BroadcastHeader => "6LoWPAN broadcast header".to_string(),
        Dispatch::IpHeaderCompression => "6LoWPAN IPHC compressed header".to_string(),
        Dispatch::Mesh => "6LoWPAN mesh header".to_string(),
        // Both fragment forms carry the size of the whole datagram and a tag
        // that groups the pieces; a later fragment adds its offset.
        Dispatch::FirstFragment => match fragment_header(payload) {
            Some((size, tag)) => {
                format!("6LoWPAN fragment 1 of datagram {tag} ({size} bytes total)")
            }
            None => "6LoWPAN fragment (truncated header)".to_string(),
        },
        Dispatch::LaterFragment => {
            match fragment_header(payload) {
                Some((size, tag)) => {
                    let offset = payload.get(4).map(|o| *o as u16 * 8).unwrap_or(0);
                    format!("6LoWPAN fragment at offset {offset} of datagram {tag} ({size} bytes total)")
                }
                None => "6LoWPAN fragment (truncated header)".to_string(),
            }
        }
    };
    result(summary)
}

/// Read the datagram size and tag common to both fragment headers.
///
/// The size is 11 bits, sharing its first byte with the dispatch pattern, so
/// the top five bits have to be masked off.
fn fragment_header(payload: &[u8]) -> Option<(u16, u16)> {
    let size = u16::from_be_bytes([payload.first()? & 0x07, *payload.get(1)?]);
    let tag = u16::from_be_bytes([*payload.get(2)?, *payload.get(3)?]);
    Some((size, tag))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressed_header_is_recognised() {
        let r = dissect_sixlowpan(&[0x60, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::SixLowpan);
        assert_eq!(r.summary, "6LoWPAN IPHC compressed header");
    }

    #[test]
    fn uncompressed_and_mesh_are_distinguished() {
        assert_eq!(
            dissect_sixlowpan(&[0x41, 0x60]).summary,
            "6LoWPAN uncompressed IPv6"
        );
        assert_eq!(
            dissect_sixlowpan(&[0x80, 0x00]).summary,
            "6LoWPAN mesh header"
        );
    }

    /// Fragmentation is the whole reason 6LoWPAN exists, so both halves of the
    /// scheme have to read clearly.
    #[test]
    fn fragments_report_datagram_size_tag_and_offset() {
        // First fragment: dispatch 0xC0 with size 0x0100 = 256, tag 0x0042.
        let first = [0xC1, 0x00, 0x00, 0x42, 0x60];
        assert_eq!(
            dissect_sixlowpan(&first).summary,
            "6LoWPAN fragment 1 of datagram 66 (256 bytes total)"
        );
        // Later fragment adds an offset in units of eight bytes.
        let later = [0xE1, 0x00, 0x00, 0x42, 0x0A];
        assert_eq!(
            dissect_sixlowpan(&later).summary,
            "6LoWPAN fragment at offset 80 of datagram 66 (256 bytes total)"
        );
    }

    /// The datagram size shares its first byte with the dispatch pattern; not
    /// masking the dispatch bits off would report a wildly inflated size.
    #[test]
    fn datagram_size_excludes_the_dispatch_bits() {
        let (size, _) = fragment_header(&[0xC1, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(size, 256);
        let (size, _) = fragment_header(&[0xE1, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(size, 256);
    }

    /// A dispatch byte in the lowest range explicitly means "not 6LoWPAN",
    /// which is how the format tolerates other protocols sharing the radio.
    #[test]
    fn not_a_lowpan_frame_is_reported_as_such() {
        assert!(!looks_like_sixlowpan(&[0x00]));
        assert!(!looks_like_sixlowpan(&[0x3F]));
        assert!(!looks_like_sixlowpan(&[]));
        assert!(looks_like_sixlowpan(&[0x60]));
        assert!(looks_like_sixlowpan(&[0xC1]));
    }

    #[test]
    fn truncated_fragment_header_does_not_panic() {
        let r = dissect_sixlowpan(&[0xC1, 0x00]);
        assert_eq!(r.summary, "6LoWPAN fragment (truncated header)");
        let r = dissect_sixlowpan(&[]);
        assert_eq!(r.summary, "6LoWPAN (empty)");
    }
}
