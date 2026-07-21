// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Modbus RTU carried over TCP — the serial framing that never left.
//!
//! Modbus TCP wraps each request in an MBAP header: a transaction id, a
//! protocol id of zero, and a length. Modbus **RTU** is the older serial
//! framing and has none of that — just a unit address, the PDU, and a CRC.
//!
//! A great many gateways bridge a serial bus onto TCP by doing nothing at all:
//! they open port 502 and forward RTU frames unchanged. That is not Modbus TCP
//! and it does not parse as Modbus TCP — the first two bytes are an address and
//! a function code where an MBAP transaction id is expected. Read as MBAP the
//! frame is garbage, so it renders as a malformed packet or as nothing, and the
//! actual traffic on a live control network becomes invisible.
//!
//! ## What identifies it
//!
//! RTU has no header to key on, so the CRC is the identification. Every frame
//! ends with a CRC-16/MODBUS over everything before it, and a sixteen-bit
//! checksum agreeing by chance is rare enough to be a real signal — far
//! stronger evidence than any field-shape heuristic could give.
//!
//! That also makes the implementation self-checking, which matters: the
//! algorithm has a published check value (the string `123456789` encodes to
//! `0x4B37`), so a wrong polynomial, initial value or bit order produces a
//! different answer and the test catches it. The correctness of this dissector
//! rests on an external constant rather than on my reading of a document.

use std::net::IpAddr;

use crate::models::Protocol;

use super::{modbus, DissectedResult};

/// Address, function code and CRC — the smallest frame that can exist.
const MIN_FRAME: usize = 4;
/// A Modbus PDU is capped at 253 bytes, plus the address and CRC.
const MAX_FRAME: usize = 256;

/// CRC-16/MODBUS: reflected polynomial 0xA001, initial value 0xFFFF, no final
/// XOR. Verified against the published check value in the tests below.
pub(crate) fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= byte as u16;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

/// Whether a payload is an RTU frame, judged by its own checksum.
///
/// The CRC is the whole guard. RTU has no protocol identifier, no length field
/// and no magic — a shape-based test would claim ordinary binary traffic, which
/// on port 502 would mean claiming Modbus TCP frames as RTU and reporting the
/// MBAP header as an address and a function code.
pub(crate) fn looks_like_modbus_rtu(payload: &[u8]) -> bool {
    if !(MIN_FRAME..=MAX_FRAME).contains(&payload.len()) {
        return false;
    }
    // A unit address of zero is a broadcast, valid only for writes; 248-255 are
    // reserved. Checking this before the CRC costs nothing and rules out most
    // non-Modbus traffic without doing the arithmetic.
    if payload[0] > 247 {
        return false;
    }
    let (body, crc) = payload.split_at(payload.len() - 2);
    // The CRC is transmitted low byte first, unlike everything else in Modbus.
    u16::from_le_bytes([crc[0], crc[1]]) == crc16(body)
}

/// Dissect a Modbus RTU frame.
pub fn dissect_modbus_rtu(
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
        protocol: Protocol::ModbusRtu,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    let Some(&address) = payload.first() else {
        return "Modbus RTU".to_string();
    };
    let Some(&function) = payload.get(1) else {
        return format!("Modbus RTU unit {address}");
    };

    // An exception response sets the high bit of the function code and puts the
    // reason in the next byte — the same convention as Modbus TCP.
    if function & 0x80 != 0 {
        let asked = function & 0x7F;
        let reason = payload
            .get(2)
            .map(|&e| modbus::exception_name(e))
            .unwrap_or("unknown exception");
        return format!(
            "Modbus RTU unit {address} — {} refused: {reason}",
            modbus::function_name(asked)
        );
    }

    // Address zero is a broadcast: no device will answer, which is the point
    // and also why a broadcast read is a configuration mistake.
    let who = if address == 0 {
        "broadcast".to_string()
    } else {
        format!("unit {address}")
    };
    format!("Modbus RTU {who} — {}", modbus::function_name(function))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Append a valid CRC to a frame body.
    fn frame(body: &[u8]) -> Vec<u8> {
        let mut v = body.to_vec();
        v.extend_from_slice(&crc16(body).to_le_bytes());
        v
    }

    /// The published check value for CRC-16/MODBUS.
    ///
    /// This is the test that makes the rest of the module trustworthy: a wrong
    /// polynomial, a wrong initial value or the wrong bit order all produce a
    /// different number here. The implementation is checked against an external
    /// constant rather than against my own reading of a document.
    ///
    /// Swapping the polynomial for the non-reflected 0x8005 was tried, and
    /// **only this test failed** — every other test in the module builds its
    /// frames with `crc16` and so agreed with the broken version perfectly.
    /// That is what a test anchored to nothing outside itself is worth, and it
    /// is why the PER work (E5) is on hold rather than written from memory.
    #[test]
    fn the_crc_matches_the_published_check_value() {
        assert_eq!(crc16(b"123456789"), 0x4B37);
    }

    /// The reason this dissector exists: a gateway forwarding serial frames
    /// unchanged onto port 502 produces traffic that is not Modbus TCP and does
    /// not parse as it.
    #[test]
    fn a_read_request_is_named() {
        // Unit 17, Read Holding Registers, 2 registers from address 0x006B.
        let p = frame(&[0x11, 0x03, 0x00, 0x6B, 0x00, 0x02]);
        let r = dissect_modbus_rtu(None, None, 40000, 502, &p);
        assert_eq!(r.protocol, Protocol::ModbusRtu);
        assert_eq!(r.summary, "Modbus RTU unit 17 — Read Holding Registers");
    }

    /// A refusal names both what was asked and why it was refused.
    #[test]
    fn an_exception_response_says_what_was_refused_and_why() {
        // Function 3 with the high bit set, exception 2.
        let p = frame(&[0x11, 0x83, 0x02]);
        assert_eq!(
            describe(&p),
            "Modbus RTU unit 17 — Read Holding Registers refused: Illegal Data Address"
        );
    }

    /// Address zero is a broadcast, which no device answers — worth saying,
    /// because a broadcast read is a configuration mistake that looks like a
    /// dead device.
    #[test]
    fn a_broadcast_is_distinguished_from_a_unit() {
        let p = frame(&[0x00, 0x06, 0x00, 0x01, 0x00, 0x03]);
        assert_eq!(describe(&p), "Modbus RTU broadcast — Write Single Register");
    }

    /// The CRC is the whole guard, so it has to actually reject.
    #[test]
    fn recognition_rests_entirely_on_the_checksum() {
        let good = frame(&[0x11, 0x03, 0x00, 0x6B, 0x00, 0x02]);
        assert!(looks_like_modbus_rtu(&good));

        // One bit flipped anywhere in the body invalidates it.
        let mut corrupt = good.clone();
        corrupt[3] ^= 0x01;
        assert!(!looks_like_modbus_rtu(&corrupt));

        // A correct body with a wrong checksum.
        let mut bad_crc = good.clone();
        let n = bad_crc.len();
        bad_crc[n - 1] ^= 0xFF;
        assert!(!looks_like_modbus_rtu(&bad_crc));

        assert!(!looks_like_modbus_rtu(b"GET / HTTP/1.1\r\n\r\n"));
        assert!(!looks_like_modbus_rtu(&[]));
    }

    /// The CRC goes on the wire low byte first, unlike every other Modbus
    /// field. Reading it big-endian rejects every valid frame.
    #[test]
    fn the_checksum_is_little_endian_unlike_the_rest_of_modbus() {
        let body = [0x11u8, 0x03, 0x00, 0x6B, 0x00, 0x02];
        let mut swapped = body.to_vec();
        swapped.extend_from_slice(&crc16(&body).to_be_bytes());
        assert!(!looks_like_modbus_rtu(&swapped));
        assert!(looks_like_modbus_rtu(&frame(&body)));
    }

    /// Reserved addresses are not units, and rejecting them early avoids doing
    /// the arithmetic on traffic that cannot be Modbus.
    #[test]
    fn reserved_addresses_are_not_claimed() {
        let p = frame(&[0xF9, 0x03, 0x00, 0x01]);
        assert!(!looks_like_modbus_rtu(&p), "248-255 are reserved");
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "Modbus RTU");
        assert_eq!(describe(&[0x11]), "Modbus RTU unit 17");
        // An exception whose reason byte has not arrived.
        assert!(describe(&[0x11, 0x83]).contains("unknown exception"));
        // Too short to hold a frame at all.
        assert!(!looks_like_modbus_rtu(&[0x11, 0x03, 0x00]));
    }
}
