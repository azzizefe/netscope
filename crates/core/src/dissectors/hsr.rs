// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! HSR — sending everything twice so nothing is ever lost (IEC 62439-3).
//!
//! MRP heals a broken ring in tens of milliseconds. For a substation protection
//! relay that is far too slow, so HSR does not heal at all: every frame is sent
//! both ways round the ring at once, and the receiver keeps whichever copy
//! arrives first and discards the other. A cut cable costs nothing, because the
//! other copy was already on its way.
//!
//! The tag carries a sequence number, and that is what makes a capture useful.
//! Both copies of a frame carry the same number, so a receiver seeing only one
//! of each is a ring that has already lost a path — which HSR is specifically
//! designed to hide from the application, and therefore from everyone, until
//! the second path fails too.

use crate::models::Protocol;

use super::DissectedResult;

/// Path, size, sequence number, then the EtherType of what is inside.
const TAG_LEN: usize = 6;

/// Dissect an HSR-tagged frame (EtherType 0x892F).
pub fn dissect_hsr(payload: &[u8]) -> DissectedResult {
    let base = DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Hsr,
        summary: String::new(),
    };

    let Some(tag) = payload.get(..TAG_LEN) else {
        return DissectedResult {
            summary: "HSR frame (truncated tag)".into(),
            ..base
        };
    };
    // The first four bits select which way round the ring this copy went; the
    // remaining twelve are the frame's length.
    let path = tag[0] >> 4;
    let sequence = u16::from_be_bytes([tag[2], tag[3]]);
    let inner_type = u16::from_be_bytes([tag[4], tag[5]]);

    // The tag wraps an ordinary frame, so hand the payload on and prefix the
    // carrier — the innermost recognised protocol is what a reader wants.
    let inner = super::dispatch_l3(inner_type, payload.get(TAG_LEN..).unwrap_or(&[]), 0);
    DissectedResult {
        summary: format!("HSR path {path}, seq {sequence} · {}", inner.summary),
        protocol: inner.protocol,
        ..inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrap a payload in an HSR tag.
    fn tagged(path: u8, sequence: u16, inner_type: u16, inner: &[u8]) -> Vec<u8> {
        let mut p = vec![path << 4, 0x00];
        p.extend_from_slice(&sequence.to_be_bytes());
        p.extend_from_slice(&inner_type.to_be_bytes());
        p.extend_from_slice(inner);
        p
    }

    /// The tag is a wrapper, so what matters is still what is inside it — the
    /// tag is context, not the answer.
    #[test]
    fn the_inner_protocol_is_dissected_and_the_tag_prefixed() {
        // An ARP request inside an HSR tag.
        let mut arp = vec![0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01];
        arp.extend_from_slice(&[0xAA; 6]); // sender MAC
        arp.extend_from_slice(&[10, 0, 0, 1]); // sender IP
        arp.extend_from_slice(&[0x00; 6]); // target MAC
        arp.extend_from_slice(&[10, 0, 0, 2]); // target IP

        let r = dissect_hsr(&tagged(1, 0x1234, 0x0806, &arp));
        assert!(
            r.summary.starts_with("HSR path 1, seq 4660 · "),
            "{}",
            r.summary
        );
        assert!(r.summary.contains("ARP"), "{}", r.summary);
    }

    /// Both copies of a frame carry the same sequence number — that is how a
    /// receiver knows they are duplicates, and how a reader spots a ring that
    /// has quietly lost one of its two paths.
    #[test]
    fn both_copies_share_a_sequence_number_and_differ_by_path() {
        let inner = [0u8; 20];
        let a = dissect_hsr(&tagged(0, 99, 0x0800, &inner)).summary;
        let b = dissect_hsr(&tagged(1, 99, 0x0800, &inner)).summary;
        assert!(a.contains("seq 99") && b.contains("seq 99"));
        assert!(a.contains("path 0") && b.contains("path 1"));
    }

    /// A tag too short to read must not be guessed at.
    #[test]
    fn a_truncated_tag_is_reported_as_such() {
        let r = dissect_hsr(&[0x10, 0x00]);
        assert_eq!(r.protocol, Protocol::Hsr);
        assert!(r.summary.contains("truncated"));
        assert!(dissect_hsr(&[]).summary.contains("truncated"));
    }

    /// A tag wrapping nothing must not panic.
    #[test]
    fn an_empty_payload_does_not_panic() {
        let r = dissect_hsr(&tagged(0, 1, 0x0800, &[]));
        assert!(r.summary.starts_with("HSR path 0"), "{}", r.summary);
    }
}
