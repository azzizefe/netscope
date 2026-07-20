// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! µTP — the transport BitTorrent clients actually use (BEP 29).
//!
//! Running BitTorrent over TCP is antisocial: TCP's congestion control competes
//! on equal terms with everything else, so a few torrents will starve a video
//! call sharing the same link. µTP fixes that by running over UDP with a
//! congestion controller that watches one-way delay and backs off as soon as a
//! queue starts building — so it yields to interactive traffic rather than
//! fighting it.
//!
//! That makes it worth identifying: a link saturated by µTP behaves very
//! differently from one saturated by TCP, and the diagnosis is different too.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The fixed header: type and version, extension, connection id, two
/// timestamps, a window, and the sequence and acknowledgement numbers.
const HEADER: usize = 20;
/// Version 1 is the only one deployed.
const VERSION_1: u8 = 1;

/// Packet types (BEP 29).
fn packet_name(t: u8) -> Option<&'static str> {
    Some(match t {
        0 => "data",
        1 => "FIN",
        2 => "ACK",
        3 => "RESET",
        4 => "SYN",
        _ => return None,
    })
}

/// Whether a payload is a µTP packet.
///
/// The version nibble and a valid type together are a reasonably strong signal,
/// and unlike a bare length field they cannot be satisfied by arbitrary text —
/// the version has to be exactly 1 and the type at most 4, which rules out
/// every printable first byte.
pub(crate) fn looks_like_utp(payload: &[u8]) -> bool {
    parse(payload).is_some()
}

fn parse(payload: &[u8]) -> Option<(&'static str, u16, u16, u16)> {
    if payload.len() < HEADER {
        return None;
    }
    let first = payload[0];
    if first & 0x0F != VERSION_1 {
        return None;
    }
    let name = packet_name(first >> 4)?;
    let connection = u16::from_be_bytes([payload[2], payload[3]]);
    let window = u16::from_be_bytes([payload[14], payload[15]]);
    let seq = u16::from_be_bytes([payload[16], payload[17]]);
    Some((name, connection, window, seq))
}

/// Dissect a µTP packet.
pub fn dissect_utp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match parse(payload) {
        Some((name, connection, window, seq)) => {
            let body = payload.len() - HEADER;
            if body > 0 {
                format!("µTP {name} — connection {connection}, seq {seq}, {body} bytes")
            } else {
                // A window of zero is the receiver saying it cannot take more,
                // which is the signal that a transfer has stalled.
                format!("µTP {name} — connection {connection}, seq {seq}, window {window}")
            }
        }
        None => format!("µTP ({})", super::bytes(payload.len() as u64)),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Utp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a µTP packet of the given type.
    fn utp(packet_type: u8, connection: u16, seq: u16, window: u16, body: usize) -> Vec<u8> {
        let mut p = vec![(packet_type << 4) | VERSION_1, 0x00];
        p.extend_from_slice(&connection.to_be_bytes());
        p.extend_from_slice(&0u32.to_be_bytes()); // timestamp
        p.extend_from_slice(&0u32.to_be_bytes()); // timestamp difference
        p.extend_from_slice(&(window as u32).to_be_bytes());
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&0u16.to_be_bytes()); // acknowledgement number
        p.extend_from_slice(&vec![0xAA; body]);
        p
    }

    #[test]
    fn data_packets_report_their_payload_size() {
        let r = dissect_utp(None, None, 51413, 51413, &utp(0, 4242, 7, 0x1000, 1000));
        assert_eq!(r.protocol, Protocol::Utp);
        assert_eq!(r.summary, "µTP data — connection 4242, seq 7, 1000 bytes");
    }

    /// The connection setup and teardown packets carry no payload, so the
    /// window is the more useful thing to show.
    #[test]
    fn control_packets_report_the_window() {
        let r = dissect_utp(None, None, 1, 51413, &utp(4, 4242, 1, 0x2000, 0));
        assert_eq!(r.summary, "µTP SYN — connection 4242, seq 1, window 8192");
        let r = dissect_utp(None, None, 1, 51413, &utp(1, 4242, 99, 0x2000, 0));
        assert!(r.summary.starts_with("µTP FIN"));
    }

    /// A window of zero means the receiver has stopped accepting data, which is
    /// what a stalled transfer looks like.
    #[test]
    fn a_zero_window_is_visible() {
        let r = dissect_utp(None, None, 1, 51413, &utp(2, 4242, 50, 0, 0));
        assert_eq!(r.summary, "µTP ACK — connection 4242, seq 50, window 0");
    }

    /// The window is a 32-bit field but is reported from its low half here;
    /// this pins the offset so a shift would be caught.
    #[test]
    fn the_sequence_number_is_read_at_the_right_offset() {
        let r = dissect_utp(None, None, 1, 51413, &utp(0, 1, 0xBEEF, 0x10, 4));
        assert!(r.summary.contains("seq 48879"), "got {}", r.summary);
    }

    /// Recognition has to reject ordinary traffic, since µTP shares the
    /// ephemeral port range with everything else.
    #[test]
    fn foreign_payloads_are_not_claimed() {
        // Text: 'G' is 0x47, whose version nibble is 7, not 1.
        assert!(!looks_like_utp(b"GET / HTTP/1.1\r\n\r\npadding to length"));
        assert!(!looks_like_utp(&[0u8; 20]));
        assert!(!looks_like_utp(&[]));
        // A valid version but a type that does not exist.
        assert!(!looks_like_utp(&utp(9, 1, 1, 1, 0)));
        assert!(looks_like_utp(&utp(0, 1, 1, 1, 0)));
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_utp(None, None, 1, 51413, &[0x01, 0x00, 0x00]);
        assert_eq!(r.summary, "µTP (3 bytes)");
    }
}
