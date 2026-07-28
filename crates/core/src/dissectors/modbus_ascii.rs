// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Modbus ASCII carried over TCP — the other serial framing that never left.
//!
//! The sibling of [`super::modbus_rtu`], and it arrives the same way: a gateway
//! bridges a serial bus onto port 502 by forwarding frames unchanged. Where RTU
//! sends raw bytes, ASCII mode sends each byte as two ASCII hex characters
//! between a `:` and a CR LF, so a frame on the wire looks like
//! `:1103006B00027F\r\n`.
//!
//! Read as Modbus TCP that is nonsense — the MBAP transaction id comes out as
//! `":1"` and the protocol id as `"10"` — so the frame renders as malformed or
//! not at all, and real traffic on a control network stays invisible.
//!
//! ## What identifies it
//!
//! The framing does most of the work: a leading colon, a CR LF terminator, and
//! an even number of ASCII hex digits in between. The LRC then has to agree.
//!
//! Being honest about the strength of that: the LRC is eight bits, so on its own
//! it would be far weaker evidence than RTU's CRC-16 — one frame in 256 would
//! pass by chance. It is the framing constraints it is combined with that make
//! the guard decisive, not the checksum alone.

use std::net::IpAddr;

use crate::models::Protocol;

use super::{modbus, DissectedResult};

/// `:` + address + function + LRC + CR LF, every byte two characters wide.
const MIN_FRAME: usize = 9;
/// An address and a 253-byte PDU and an LRC, doubled, plus the three framing
/// characters.
const MAX_FRAME: usize = 513;

/// Longitudinal redundancy check, per the Modbus serial spec: sum the message
/// bytes discarding carries, then take the two's complement.
///
/// The defining property — and what the tests anchor to — is that the message
/// plus its own LRC sums to zero.
fn lrc(data: &[u8]) -> u8 {
    data.iter()
        .fold(0u8, |acc, &b| acc.wrapping_add(b))
        .wrapping_neg()
}

/// The binary message carried by an ASCII frame, LRC included, or `None` if the
/// framing does not hold.
///
/// Decoding is the framing check: anything that is not a colon, a CR LF and an
/// even run of hex digits in between cannot be one of these frames.
fn decode(payload: &[u8]) -> Option<Vec<u8>> {
    if !(MIN_FRAME..=MAX_FRAME).contains(&payload.len()) {
        return None;
    }
    if payload[0] != b':' || !payload.ends_with(b"\r\n") {
        return None;
    }
    let body = &payload[1..payload.len() - 2];
    if !body.len().is_multiple_of(2) {
        return None;
    }
    body.chunks_exact(2)
        .map(|pair| {
            // Uppercase is what the spec calls for; devices that send lowercase
            // are still unambiguous, so they are accepted rather than dropped.
            let hex = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(hex, 16).ok()
        })
        .collect()
}

/// Whether a payload is a Modbus ASCII frame, judged by its framing and its own
/// checksum.
pub(crate) fn looks_like_modbus_ascii(payload: &[u8]) -> bool {
    let Some(message) = decode(payload) else {
        return false;
    };
    // A unit address of zero is a broadcast; 248-255 are reserved. Same check as
    // RTU, and it rules out traffic that happens to be hex-shaped.
    if message[0] > 247 {
        return false;
    }
    // The last byte is the stated LRC; the rest is what it covers. decode()
    // guarantees at least three bytes, so this never splits an empty message.
    let (&stated, covered) = message.split_last().expect("decode enforces MIN_FRAME");
    lrc(covered) == stated
}

/// Dissect a Modbus ASCII frame.
pub fn dissect_modbus_ascii(
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
        protocol: Protocol::ModbusAscii,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    let Some(message) = decode(payload) else {
        return "Modbus ASCII".to_string();
    };
    // decode() guarantees at least the address, function and LRC.
    let address = message[0];
    let function = message[1];

    // An exception response sets the high bit of the function code and puts the
    // reason in the next byte — the same convention as RTU and Modbus TCP.
    if function & 0x80 != 0 {
        let asked = function & 0x7F;
        // The byte after the function is the reason; the one after that is the
        // LRC, so a frame with nothing between them carries no reason at all.
        let reason = if message.len() > 3 {
            modbus::exception_name(message[2])
        } else {
            "unknown exception"
        };
        return format!(
            "Modbus ASCII unit {address} — {} refused: {reason}",
            modbus::function_name(asked)
        );
    }

    // Address zero is a broadcast: no device will answer, which is the point and
    // also why a broadcast read is a configuration mistake.
    let who = if address == 0 {
        "broadcast".to_string()
    } else {
        format!("unit {address}")
    };
    format!("Modbus ASCII {who} — {}", modbus::function_name(function))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrap a binary message in ASCII framing with a correct LRC.
    fn frame(message: &[u8]) -> Vec<u8> {
        let mut s = String::from(":");
        for &b in message {
            s.push_str(&format!("{b:02X}"));
        }
        s.push_str(&format!("{:02X}", lrc(message)));
        s.push_str("\r\n");
        s.into_bytes()
    }

    /// A frame written out by hand, so the module is checked against something
    /// other than its own encoder.
    ///
    /// Unit 17, Read Holding Registers, two registers from 0x006B. The bytes sum
    /// to 0x11 + 0x03 + 0x6B + 0x02 = 0x81, and the two's complement of that is
    /// 0x7F — which is the last pair before the terminator.
    const HAND_WRITTEN: &[u8] = b":1103006B00027F\r\n";

    #[test]
    fn the_checksum_matches_a_hand_computed_frame() {
        assert_eq!(lrc(&[0x11, 0x03, 0x00, 0x6B, 0x00, 0x02]), 0x7F);
        assert_eq!(frame(&[0x11, 0x03, 0x00, 0x6B, 0x00, 0x02]), HAND_WRITTEN);
    }

    /// The defining property of a two's-complement checksum, stated directly:
    /// the message plus its own LRC is zero. A wrong sign or a missing carry
    /// discard breaks this for some input.
    #[test]
    fn a_message_plus_its_checksum_is_zero() {
        for message in [
            &[0x01u8, 0x03][..],
            &[0x11, 0x03, 0x00, 0x6B, 0x00, 0x02][..],
            &[0xF7, 0x10, 0xFF, 0xFF, 0xFF][..],
            &[0x00; 8][..],
        ] {
            let sum = message
                .iter()
                .fold(0u8, |a, &b| a.wrapping_add(b))
                .wrapping_add(lrc(message));
            assert_eq!(sum, 0, "{message:02X?}");
        }
    }

    /// The reason this dissector exists: a gateway forwarding ASCII frames onto
    /// port 502 produces traffic that is not Modbus TCP and does not parse as
    /// it. Until the guard below was implemented it returned `false` for every
    /// input, so this path was wired up and dead.
    #[test]
    fn a_read_request_is_named() {
        let r = dissect_modbus_ascii(None, None, 40000, 502, HAND_WRITTEN);
        assert_eq!(r.protocol, Protocol::ModbusAscii);
        assert_eq!(r.summary, "Modbus ASCII unit 17 — Read Holding Registers");
    }

    /// A refusal names both what was asked and why it was refused.
    #[test]
    fn an_exception_response_says_what_was_refused_and_why() {
        let p = frame(&[0x11, 0x83, 0x02]);
        assert_eq!(
            describe(&p),
            "Modbus ASCII unit 17 — Read Holding Registers refused: Illegal Data Address"
        );
    }

    /// A broadcast is not a unit — no device answers one, so a broadcast read
    /// is a configuration mistake that looks like a dead device.
    #[test]
    fn a_broadcast_is_distinguished_from_a_unit() {
        let p = frame(&[0x00, 0x06, 0x00, 0x01, 0x00, 0x03]);
        assert_eq!(
            describe(&p),
            "Modbus ASCII broadcast — Write Single Register"
        );
    }

    /// The framing is most of the guard, so each part of it has to reject on
    /// its own.
    #[test]
    fn the_framing_is_required_in_full() {
        let good = frame(&[0x11, 0x03, 0x00, 0x6B, 0x00, 0x02]);
        assert!(looks_like_modbus_ascii(&good));

        // No leading colon.
        assert!(!looks_like_modbus_ascii(&good[1..]));

        // No CR LF terminator.
        assert!(!looks_like_modbus_ascii(&good[..good.len() - 2]));

        // An odd number of hex characters cannot be whole bytes.
        let mut odd = good.clone();
        odd.insert(1, b'0');
        assert!(!looks_like_modbus_ascii(&odd));

        // A non-hex character in the body.
        let mut not_hex = good.clone();
        not_hex[3] = b'Z';
        assert!(!looks_like_modbus_ascii(&not_hex));
    }

    /// The checksum has to actually reject, or the framing alone would claim
    /// any hex-shaped line.
    #[test]
    fn the_checksum_has_to_agree() {
        let good = frame(&[0x11, 0x03, 0x00, 0x6B, 0x00, 0x02]);
        assert!(looks_like_modbus_ascii(&good));

        // A digit changed in the body, leaving the stated LRC behind.
        let mut corrupt = good.clone();
        corrupt[5] = if corrupt[5] == b'0' { b'1' } else { b'0' };
        assert!(!looks_like_modbus_ascii(&corrupt));

        // A correct body with a wrong LRC.
        let mut bad_lrc = good.clone();
        let n = bad_lrc.len();
        bad_lrc[n - 3] = if bad_lrc[n - 3] == b'F' { b'0' } else { b'F' };
        assert!(!looks_like_modbus_ascii(&bad_lrc));
    }

    /// Lowercase hex is off-spec but unambiguous, so it is read rather than
    /// dropped.
    #[test]
    fn lowercase_hex_is_accepted() {
        let lower = b":1103006b00027f\r\n";
        assert!(looks_like_modbus_ascii(lower));
        assert_eq!(
            describe(lower),
            "Modbus ASCII unit 17 — Read Holding Registers"
        );
    }

    /// Reserved addresses are not units.
    #[test]
    fn reserved_addresses_are_not_claimed() {
        let p = frame(&[0xF9, 0x03, 0x00, 0x01]);
        assert!(!looks_like_modbus_ascii(&p), "248-255 are reserved");
    }

    /// Ordinary text that happens to reach this guard is not claimed.
    #[test]
    fn unrelated_traffic_is_not_claimed() {
        assert!(!looks_like_modbus_ascii(b"GET / HTTP/1.1\r\n\r\n"));
        assert!(!looks_like_modbus_ascii(b""));
        assert!(!looks_like_modbus_ascii(b":\r\n"));
        // A Modbus TCP frame on the same port must not be taken for this.
        assert!(!looks_like_modbus_ascii(&[
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x11, 0x03, 0x00, 0x6B, 0x00, 0x02,
        ]));
    }

    /// Anything the framing rejects still renders, and nothing panics.
    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "Modbus ASCII");
        assert_eq!(describe(b":11\r\n"), "Modbus ASCII");
        // An exception whose reason byte has not arrived — address, function
        // and LRC only.
        assert!(describe(&frame(&[0x11, 0x83])).contains("unknown exception"));
    }

    #[test]
    fn handle_empty_payload() {
        let res = dissect_modbus_ascii(None, None, 0, 0, &[]);
        assert_eq!(res.protocol, Protocol::ModbusAscii);
    }
}
