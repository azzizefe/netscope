// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Aeron — reliable messaging for systems that cannot wait for TCP.
//!
//! Aeron carries messages between processes at latencies TCP cannot reach, and
//! trading systems, market-data feeds and low-latency pipelines are built on
//! it. It does over UDP what TCP does over IP, but with the loss recovery moved
//! into the application's hands: the receiver notices a gap and asks for the
//! missing range by name.
//!
//! ## Why the control frames are the interesting ones
//!
//! Data frames say nothing except that traffic is flowing. The other three say
//! what is going wrong:
//!
//! * **NAK** — the receiver is missing a range and asking for it again. An
//!   occasional one is ordinary on a busy network; a stream of them is a
//!   publisher outrunning the path, and it is the earliest warning that
//!   latency is about to become loss.
//! * **Status message** — the receiver advertising how much window it has
//!   left. A window shrinking towards zero is a consumer that cannot keep up,
//!   and the publisher will stall when it reaches zero. That stall shows up in
//!   an application as a latency spike with no obvious cause.
//! * **Setup** — a publication starting. Repeated setups for the same stream
//!   mean a publisher that keeps restarting.
//!
//! Every stream is identified by a session, a stream and a term identifier
//! together; two of the three matching is a different stream, which is why all
//! three are reported.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Frame length, version, flags, type — the header every frame shares.
const BASIC_HEADER: usize = 8;
/// The only version defined.
const VERSION: u8 = 0;

const TYPE_PAD: u16 = 0x0000;
const TYPE_DATA: u16 = 0x0001;
const TYPE_NAK: u16 = 0x0002;
const TYPE_STATUS: u16 = 0x0003;
const TYPE_ERROR: u16 = 0x0004;
const TYPE_SETUP: u16 = 0x0005;
const TYPE_RTT: u16 = 0x0006;
const TYPE_RESOLUTION: u16 = 0x0007;

fn frame_type(kind: u16) -> Option<&'static str> {
    Some(match kind {
        TYPE_PAD => "padding",
        TYPE_DATA => "data",
        TYPE_NAK => "NAK — a receiver is missing a range",
        TYPE_STATUS => "status",
        TYPE_ERROR => "error",
        TYPE_SETUP => "setup — a publication starting",
        TYPE_RTT => "round-trip measurement",
        TYPE_RESOLUTION => "name resolution",
        _ => return None,
    })
}

/// Whether a payload is an Aeron frame.
///
/// Aeron has no magic, so recognition rests on the version being the only one
/// defined, a frame type the protocol lists, and the declared length agreeing
/// with what arrived. The length check is what does most of the work.
pub(crate) fn looks_like_aeron(payload: &[u8]) -> bool {
    let Some(head) = payload.get(..BASIC_HEADER) else {
        return false;
    };
    if head[4] != VERSION {
        return false;
    }
    let kind = u16::from_le_bytes([head[6], head[7]]);
    if frame_type(kind).is_none() {
        return false;
    }
    // Everything in Aeron is little-endian, including the length.
    let declared = u32::from_le_bytes([head[0], head[1], head[2], head[3]]) as usize;
    // The length must agree with the datagram, and Aeron aligns its frames to
    // 32 bits. Both checks are load-bearing: without them this test matched a
    // DTLS record, whose version bytes happen to sit where Aeron's version and
    // type do.
    //
    // A padding frame's declared length can legitimately exceed the datagram —
    // it describes the gap being filled in the term buffer, not the bytes on
    // the wire — but exempting it opened exactly that hole, and padding frames
    // carry no information worth the false positives. They are not claimed.
    declared >= BASIC_HEADER && declared <= payload.len() && declared.is_multiple_of(4)
}

/// Dissect an Aeron frame.
pub fn dissect_aeron(
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
        protocol: Protocol::Aeron,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    let Some(head) = payload.get(..BASIC_HEADER) else {
        return "Aeron".to_string();
    };
    let kind = u16::from_le_bytes([head[6], head[7]]);
    let Some(name) = frame_type(kind) else {
        return format!("Aeron (frame type {kind:#06x})");
    };

    // Session, stream and term identify the publication. They sit at the same
    // offsets in every frame that has them.
    let stream = payload
        .get(12..24)
        .map(|b| {
            (
                u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
                u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
                u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
            )
        })
        .map(|(session, stream, term)| {
            format!(" [session {session}, stream {stream}, term {term}]")
        })
        .unwrap_or_default();

    format!("Aeron {name}{stream}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an Aeron frame of the given type.
    fn frame(kind: u16, session: u32, stream_id: u32, term: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&0u32.to_le_bytes()); // length, filled in below
        v.push(VERSION);
        v.push(0x00); // flags
        v.extend_from_slice(&kind.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes()); // term offset
        v.extend_from_slice(&session.to_le_bytes());
        v.extend_from_slice(&stream_id.to_le_bytes());
        v.extend_from_slice(&term.to_le_bytes());
        let len = v.len() as u32;
        v[..4].copy_from_slice(&len.to_le_bytes());
        v
    }

    /// The reason this dissector exists: the control frames say what is going
    /// wrong, and a data frame says only that traffic exists.
    #[test]
    fn a_nak_is_reported_as_a_receiver_missing_data() {
        let r = dissect_aeron(None, None, 40000, 40001, &frame(TYPE_NAK, 7, 3, 11));
        assert_eq!(r.protocol, Protocol::Aeron);
        assert_eq!(
            r.summary,
            "Aeron NAK — a receiver is missing a range [session 7, stream 3, term 11]"
        );
    }

    /// A stream is identified by all three numbers together; two matching is a
    /// different stream, so all three are reported.
    #[test]
    fn the_publication_is_identified_by_three_numbers() {
        let a = describe(&frame(TYPE_DATA, 1, 2, 3));
        let b = describe(&frame(TYPE_DATA, 1, 2, 4));
        assert!(a.contains("session 1, stream 2, term 3"), "{a}");
        assert_ne!(a, b, "a different term is a different stream");
    }

    #[test]
    fn the_control_frame_types_are_named() {
        assert!(describe(&frame(TYPE_SETUP, 1, 1, 1)).contains("a publication starting"));
        assert!(describe(&frame(TYPE_STATUS, 1, 1, 1)).contains("status"));
        assert!(describe(&frame(TYPE_RTT, 1, 1, 1)).contains("round-trip"));
        assert!(describe(&frame(TYPE_ERROR, 1, 1, 1)).contains("error"));
    }

    /// Aeron has no magic, so the version, a known type and a length that
    /// agrees with the packet are all the evidence there is.
    #[test]
    fn recognition_rests_on_the_version_type_and_length() {
        assert!(looks_like_aeron(&frame(TYPE_DATA, 1, 1, 1)));

        // A version the protocol does not define.
        let mut wrong_version = frame(TYPE_DATA, 1, 1, 1);
        wrong_version[4] = 1;
        assert!(!looks_like_aeron(&wrong_version));

        // A frame type outside the list.
        let mut wrong_type = frame(TYPE_DATA, 1, 1, 1);
        wrong_type[6] = 0x99;
        assert!(!looks_like_aeron(&wrong_type));

        // A length longer than the packet.
        let mut wrong_length = frame(TYPE_DATA, 1, 1, 1);
        wrong_length[..4].copy_from_slice(&9999u32.to_le_bytes());
        assert!(!looks_like_aeron(&wrong_length));

        assert!(!looks_like_aeron(b"GET / HTTP/1.1\r\n"));
        assert!(!looks_like_aeron(&[]));
    }

    /// Everything in Aeron is little-endian, so a big-endian read of the type
    /// turns every data frame into an unknown one.
    #[test]
    fn the_header_is_little_endian() {
        // Type 1 little-endian is 0x01 0x00; read big-endian it is 0x0100.
        let data = frame(TYPE_DATA, 1, 1, 1);
        assert_eq!(data[6], 0x01);
        assert_eq!(data[7], 0x00);
        assert!(describe(&data).contains("Aeron data"));
    }

    /// The guard must not claim other protocols. This is not hypothetical:
    /// exempting padding frames from the length check made it match a DTLS
    /// record, because DTLS's version bytes land where Aeron's version and
    /// frame type sit.
    #[test]
    fn a_dtls_record_is_not_claimed_as_aeron() {
        let mut dtls = vec![22, 0xFE, 0xFD, 0x00, 0x00];
        dtls.extend_from_slice(&[0u8; 8]);
        assert!(!looks_like_aeron(&dtls));
    }

    /// Aeron aligns its frames to 32 bits, which rules out most lengths that
    /// would otherwise pass by chance.
    #[test]
    fn an_unaligned_length_is_not_claimed() {
        let mut odd = frame(TYPE_DATA, 1, 1, 1);
        odd[..4].copy_from_slice(&9u32.to_le_bytes());
        assert!(!looks_like_aeron(&odd));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "Aeron");
        assert_eq!(describe(&[0u8; 7]), "Aeron");
        // A header with no identifiers after it.
        assert_eq!(
            describe(&[0x08, 0, 0, 0, VERSION, 0, 0x01, 0x00]),
            "Aeron data"
        );
        assert_eq!(
            describe(&[0x08, 0, 0, 0, VERSION, 0, 0x99, 0x00]),
            "Aeron (frame type 0x0099)"
        );
    }
}
