// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! AMQP 1.0 — a different protocol from AMQP 0-9-1, sharing its port.
//!
//! The two are related only by name. 0-9-1 is what RabbitMQ speaks natively;
//! 1.0 is the OASIS and ISO standard behind Azure Service Bus, Apache Qpid and
//! ActiveMQ Artemis. They share TCP 5672 and are told apart by the version in
//! the opening protocol header, so a dissector that assumes one will misread
//! the other entirely.
//!
//! The performative — the verb of each frame — is what says whether a message
//! is moving: a `transfer` carries one, a `disposition` settles it, and a
//! `flow` is a receiver adjusting how many more it will accept, which is what
//! back-pressure looks like on the wire.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The protocol header: "AMQP", a protocol id, then the version.
const PROTOCOL_HEADER: usize = 8;
const MARKER: &[u8] = b"AMQP";

/// Frame size, data offset, type, channel.
const FRAME_HEADER: usize = 8;
const FRAME_TYPE_AMQP: u8 = 0x00;
const FRAME_TYPE_SASL: u8 = 0x01;

/// Performative descriptors, encoded as a small ulong after the descriptor
/// constructor (§2.7).
fn performative_name(code: u8) -> Option<&'static str> {
    Some(match code {
        0x10 => "open (connection)",
        0x11 => "begin (session)",
        0x12 => "attach (link)",
        0x13 => "flow (credit)",
        0x14 => "transfer (message)",
        0x15 => "disposition (settle)",
        0x16 => "detach",
        0x17 => "end (session)",
        0x18 => "close (connection)",
        _ => return None,
    })
}

/// SASL frames negotiate authentication before the connection proper.
fn sasl_name(code: u8) -> Option<&'static str> {
    Some(match code {
        0x40 => "SASL mechanisms offered",
        0x41 => "SASL init",
        0x42 => "SASL challenge",
        0x43 => "SASL response",
        0x44 => "SASL outcome",
        _ => return None,
    })
}

/// Whether a payload is the AMQP 1.0 protocol header.
///
/// The version is what separates this from 0-9-1 on the shared port, so the
/// check is exact rather than just looking for the marker.
pub(crate) fn is_amqp1_header(payload: &[u8]) -> bool {
    payload.len() >= PROTOCOL_HEADER && payload.starts_with(MARKER) && payload[5] == 1
}

/// Whether a payload is AMQP 1.0 rather than 0-9-1, header or frame.
///
/// The protocol header only appears once, at the start of a connection, so a
/// capture joined mid-stream has to be told apart from the frames themselves.
/// The two framings disagree on the first byte, which is decisive rather than
/// merely suggestive: 0-9-1 opens with a frame type of 1, 2, 3 or 8, while 1.0
/// opens with the top byte of a 32-bit frame size — zero for any frame below
/// sixteen megabytes, which the negotiated maximum keeps them under.
pub(crate) fn looks_like_amqp1(payload: &[u8]) -> bool {
    if is_amqp1_header(payload) {
        return true;
    }
    payload.len() >= FRAME_HEADER
        && payload[0] == 0x00
        // A data offset below two words would overlap the header itself.
        && payload[4] >= 2
        && matches!(payload[5], FRAME_TYPE_AMQP | FRAME_TYPE_SASL)
}

/// Dissect an AMQP 1.0 frame.
pub fn dissect_amqp1(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = describe(payload);
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Amqp1,
        summary,
    }
}

fn describe(payload: &[u8]) -> String {
    if payload.starts_with(MARKER) && payload.len() >= PROTOCOL_HEADER {
        // Protocol id 3 is the SASL layer, 0 the connection itself.
        let layer = match payload[4] {
            0 => "connection",
            2 => "TLS",
            3 => "SASL",
            other => return format!("AMQP 1.0 protocol header (id {other})"),
        };
        return format!(
            "AMQP 1.0 protocol header — {layer}, v{}.{}.{}",
            payload[5], payload[6], payload[7]
        );
    }
    if payload.len() < FRAME_HEADER {
        return format!("AMQP 1.0 ({})", super::bytes(payload.len() as u64));
    }
    let frame_type = payload[5];
    let channel = u16::from_be_bytes([payload[6], payload[7]]);
    // The data offset is in 4-byte words and may leave extended header bytes
    // before the body, so the performative is not at a fixed offset.
    let body_at = payload[4] as usize * 4;

    // The body opens with a descriptor: 0x00 then a small ulong naming the
    // performative.
    let code = payload
        .get(body_at)
        .filter(|&&b| b == 0x00)
        .and(payload.get(body_at + 1))
        .filter(|&&b| b == 0x53 || b == 0x44)
        .and(payload.get(body_at + 2))
        .copied();

    match (frame_type, code) {
        (FRAME_TYPE_AMQP, Some(c)) => match performative_name(c) {
            Some(name) => format!("AMQP 1.0 {name} (channel {channel})"),
            None => format!("AMQP 1.0 performative 0x{c:02x} (channel {channel})"),
        },
        (FRAME_TYPE_SASL, Some(c)) => match sasl_name(c) {
            Some(name) => format!("AMQP 1.0 {name}"),
            None => format!("AMQP 1.0 SASL frame 0x{c:02x}"),
        },
        (FRAME_TYPE_AMQP, None) => format!("AMQP 1.0 empty frame (channel {channel})"),
        (FRAME_TYPE_SASL, None) => "AMQP 1.0 SASL frame".to_string(),
        (other, _) => format!("AMQP 1.0 frame type {other} (channel {channel})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a frame carrying the given performative.
    fn frame(frame_type: u8, channel: u16, code: u8) -> Vec<u8> {
        let body = [0x00u8, 0x53, code, 0xC0]; // descriptor, small ulong, list
        let mut p = ((FRAME_HEADER + body.len()) as u32).to_be_bytes().to_vec();
        p.push(2); // data offset: two words, so no extended header
        p.push(frame_type);
        p.extend_from_slice(&channel.to_be_bytes());
        p.extend_from_slice(&body);
        p
    }

    /// The version in the header is the only thing separating this from
    /// AMQP 0-9-1 on the same port.
    #[test]
    fn the_version_distinguishes_it_from_amqp_0_9_1() {
        assert!(is_amqp1_header(b"AMQP\x00\x01\x00\x00"));
        // A 0-9-1 header carries version 0.9.1 and must not be claimed.
        assert!(!is_amqp1_header(b"AMQP\x00\x00\x09\x01"));
        assert!(!is_amqp1_header(b"AMQP"));
        assert!(!is_amqp1_header(b"GET / HTTP/1.1"));
    }

    #[test]
    fn the_protocol_header_names_its_layer() {
        let r = dissect_amqp1(None, None, 40000, 5672, b"AMQP\x00\x01\x00\x00");
        assert_eq!(r.protocol, Protocol::Amqp1);
        assert_eq!(r.summary, "AMQP 1.0 protocol header — connection, v1.0.0");
        let r = dissect_amqp1(None, None, 1, 5672, b"AMQP\x03\x01\x00\x00");
        assert_eq!(r.summary, "AMQP 1.0 protocol header — SASL, v1.0.0");
    }

    /// A transfer is a message moving; everything else is bookkeeping.
    #[test]
    fn a_transfer_is_distinguished_from_bookkeeping() {
        assert_eq!(
            dissect_amqp1(None, None, 1, 5672, &frame(FRAME_TYPE_AMQP, 1, 0x14)).summary,
            "AMQP 1.0 transfer (message) (channel 1)"
        );
        assert_eq!(
            dissect_amqp1(None, None, 1, 5672, &frame(FRAME_TYPE_AMQP, 1, 0x15)).summary,
            "AMQP 1.0 disposition (settle) (channel 1)"
        );
    }

    /// A flow frame is a receiver saying how many more messages it will take,
    /// so a run of them with little transfer is back-pressure.
    #[test]
    fn credit_and_teardown_are_named() {
        assert_eq!(
            dissect_amqp1(None, None, 1, 5672, &frame(FRAME_TYPE_AMQP, 2, 0x13)).summary,
            "AMQP 1.0 flow (credit) (channel 2)"
        );
        assert_eq!(
            dissect_amqp1(None, None, 1, 5672, &frame(FRAME_TYPE_AMQP, 0, 0x18)).summary,
            "AMQP 1.0 close (connection) (channel 0)"
        );
    }

    /// Authentication happens on its own frame type before the connection
    /// opens, and a failure there explains everything that does not follow.
    #[test]
    fn sasl_frames_are_named() {
        assert_eq!(
            dissect_amqp1(None, None, 1, 5672, &frame(FRAME_TYPE_SASL, 0, 0x40)).summary,
            "AMQP 1.0 SASL mechanisms offered"
        );
        assert_eq!(
            dissect_amqp1(None, None, 1, 5672, &frame(FRAME_TYPE_SASL, 0, 0x44)).summary,
            "AMQP 1.0 SASL outcome"
        );
    }

    /// The data offset can leave extended header bytes before the body, so the
    /// performative is not at a fixed position.
    #[test]
    fn an_extended_header_shifts_the_performative() {
        let body = [0x00u8, 0x53, 0x14, 0xC0];
        let mut p = 20u32.to_be_bytes().to_vec();
        p.push(3); // three words: eight bytes of header plus four extended
        p.push(FRAME_TYPE_AMQP);
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&[0xAA; 4]); // the extended header
        p.extend_from_slice(&body);
        assert_eq!(
            dissect_amqp1(None, None, 1, 5672, &p).summary,
            "AMQP 1.0 transfer (message) (channel 1)"
        );
    }

    /// An empty frame is a heartbeat, not a parse failure.
    #[test]
    fn an_empty_frame_is_recognised() {
        let p = [0x00, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x00];
        assert_eq!(
            dissect_amqp1(None, None, 1, 5672, &p).summary,
            "AMQP 1.0 empty frame (channel 0)"
        );
    }

    /// A capture joined after the connection opened has no protocol header to
    /// go on, so the framing itself has to separate the two protocols.
    #[test]
    fn mid_stream_frames_are_told_apart_from_amqp_0_9_1() {
        assert!(looks_like_amqp1(&frame(FRAME_TYPE_AMQP, 1, 0x14)));
        assert!(looks_like_amqp1(&frame(FRAME_TYPE_SASL, 0, 0x41)));

        // AMQP 0-9-1 frames open with a type of 1, 2, 3 or 8 — never zero —
        // followed by a channel and a size.
        for frame_type in [1u8, 2, 3, 8] {
            let mut p = vec![frame_type, 0x00, 0x01];
            p.extend_from_slice(&4u32.to_be_bytes());
            p.extend_from_slice(&[0x00, 0x0A, 0x00, 0x0B, 0xCE]);
            assert!(
                !looks_like_amqp1(&p),
                "claimed a 0-9-1 type {frame_type} frame"
            );
        }
    }

    /// A data offset below two words would put the body inside the header, so
    /// it means this is not a frame at all.
    #[test]
    fn an_impossible_data_offset_is_rejected() {
        let mut p = frame(FRAME_TYPE_AMQP, 1, 0x14);
        p[4] = 1;
        assert!(!looks_like_amqp1(&p));
        assert!(!looks_like_amqp1(&[]));
        assert!(!looks_like_amqp1(b"GET / HTTP/1.1\r\n\r\n"));
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_amqp1(None, None, 1, 5672, &[0x00, 0x00, 0x00]);
        assert_eq!(r.summary, "AMQP 1.0 (3 bytes)");
    }
}
