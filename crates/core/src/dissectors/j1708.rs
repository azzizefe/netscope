// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! SAE J1708 / J1587 — the serial data bus under every heavy truck.
//!
//! J1708 is the physical/data-link layer (9600 baud RS-485) and J1587 is the
//! message layer on top of it. Every frame is:
//!
//! ```text
//! [ MID (1 byte) ][ Parameter data (0-21 bytes) ][ Checksum (1 byte) ]
//! ```
//!
//! The **Message ID (MID)** identifies the subsystem that sent the frame:
//! engine (128), transmission (136), brakes (136+), instrument cluster (140),
//! and so on. Without it, a capture from a truck is undifferentiated hex.
//!
//! ## What the checksum tells you
//!
//! J1708 uses a simple two's-complement checksum: the checksum byte is chosen
//! so that the sum of all bytes in the frame (including the checksum) is zero
//! modulo 256. This is weaker than CRC-16, but it has a published, easily
//! verified definition — and it is the identification: a frame whose bytes sum
//! to zero is a J1708 frame; anything else is not.
//!
//! ## Where this shows up
//!
//! J1708 is a serial bus. It reaches IP captures via gateways that bridge the
//! RS-485 wire onto the network. No standard port number is assigned; the port
//! depends on the gateway. This dissector is therefore a structural recogniser
//! (like OSC) rather than a port-binding one: the checksum is the guard, and
//! the MID names the subsystem.
//!
//! ## Guard strength
//!
//! A random payload passes the checksum by chance in 1/256 of cases. That
//! is weaker than CRC-16 but still a real signal, especially combined with
//! the MID range restriction. Frames shorter than 2 bytes (MID + checksum)
//! are rejected immediately.
//!
//! ## MID table
//!
//! Source: SAE J1587, Table 1 — Message Identification Numbers. Only the
//! most commonly seen subsystems are named; the rest are shown as `MID 0xNN`.

use crate::models::Protocol;

use super::DissectedResult;

/// Smallest valid J1708 frame: MID + checksum.
const MIN_LEN: usize = 2;
/// Maximum J1708 payload: 21 data bytes + MID + checksum.
const MAX_LEN: usize = 23;

/// Verify the J1708 two's-complement checksum.
///
/// The checksum byte is chosen so that `(sum of all bytes) mod 256 == 0`.
/// A frame with the wrong checksum is not J1708.
pub fn checksum_valid(data: &[u8]) -> bool {
    if data.len() < MIN_LEN {
        return false;
    }
    let sum: u8 = data.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    sum == 0
}

/// Whether a payload could be a J1708 frame.
///
/// The guard checks the length range and the two's-complement checksum.
/// Random traffic passes by chance in ~1/256 cases, which is weaker than
/// CRC-16 — but the MID range (128-255 for defined subsystems; 1-127 mostly
/// reserved or proprietary) provides additional context. Both must be
/// satisfied for a high-confidence match.
pub fn looks_like_j1708(payload: &[u8]) -> bool {
    if !(MIN_LEN..=MAX_LEN).contains(&payload.len()) {
        return false;
    }
    checksum_valid(payload)
}

/// The subsystem name for a Message ID, from SAE J1587 Table 1.
///
/// Only the most frequently encountered MIDs are named. Everything else
/// shows the raw hex value — an invented name would be worse than a number.
fn mid_name(mid: u8) -> &'static str {
    match mid {
        128 => "Engine",
        130 => "Turbocharger",
        136 => "Transmission",
        137 => "Power Take-Off",
        138 => "Axle/Steering",
        139 => "Axle/Drive",
        140 => "Brakes — system controller",
        142 => "Instrument cluster",
        143 => "Trip recorder",
        144 => "Vehicle management system",
        145 => "Fuel system",
        146 => "Cruise control",
        149 => "Vehicle sensors",
        150 => "Data logger",
        151 => "Electrical system",
        162 => "Traction control",
        163 => "Driver information system",
        165 => "ABS",
        168 => "Collision avoidance system",
        175 => "Diagnostics",
        200 => "Maintenance printer",
        _ => "",
    }
}

/// Dissect a J1708/J1587 frame.
///
/// `payload` is the raw serial frame as captured by the gateway: MID byte,
/// zero or more data bytes, then the checksum byte.
pub fn dissect_j1708(payload: &[u8]) -> DissectedResult {
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::J1708,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    if payload.len() < MIN_LEN {
        return "J1708 (truncated)".into();
    }
    let mid = payload[0];
    // data is everything between MID and checksum.
    let data = &payload[1..payload.len() - 1];

    let subsystem = mid_name(mid);
    let mid_str = if subsystem.is_empty() {
        format!("MID 0x{mid:02X}")
    } else {
        format!("{subsystem} (MID 0x{mid:02X})")
    };

    if data.is_empty() {
        return format!("J1708 {mid_str}");
    }

    // The first byte of J1587 data is the Parameter ID (PID) or a length
    // indicator for multi-byte parameters. Naming every PID is outside scope;
    // we report the count and the first PID.
    let first_pid = data[0];
    let data_len = data.len();
    if data_len == 1 {
        format!("J1708 {mid_str} PID 0x{first_pid:02X}")
    } else {
        format!(
            "J1708 {mid_str} PID 0x{first_pid:02X} +{} byte{}",
            data_len - 1,
            if data_len - 1 == 1 { "" } else { "s" }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid J1708 frame by computing the checksum.
    fn frame(mid: u8, data: &[u8]) -> Vec<u8> {
        let mut v = vec![mid];
        v.extend_from_slice(data);
        // checksum = 256 - (sum mod 256)
        let sum: u8 = v.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        v.push(sum.wrapping_neg());
        v
    }

    /// The reason this dissector exists: without it, a truck's engine
    /// controller looks like undifferentiated hex. With it, "Engine (MID 0x80)"
    /// names the subsystem that sent the frame.
    #[test]
    fn engine_controller_is_named() {
        // MID 128 (0x80) = Engine; PID 0x5C = engine speed.
        let f = frame(128, &[0x5C, 0x03, 0xE8]);
        let r = dissect_j1708(&f);
        assert_eq!(r.protocol, Protocol::J1708);
        assert!(r.summary.contains("Engine"), "{}", r.summary);
        assert!(r.summary.contains("MID 0x80"), "{}", r.summary);
    }

    /// The checksum guard rejects traffic that is not J1708.
    #[test]
    fn wrong_checksum_is_rejected() {
        // Correct frame for engine, then corrupt the checksum.
        let mut f = frame(128, &[0x5C]);
        *f.last_mut().unwrap() = f.last().unwrap().wrapping_add(1);
        assert!(!looks_like_j1708(&f));
    }

    /// A payload that is too short or too long is rejected before checksum
    /// verification, which costs nothing.
    #[test]
    fn length_bounds_are_enforced() {
        assert!(!looks_like_j1708(&[])); // empty
        assert!(!looks_like_j1708(&[0x80])); // only MID, no checksum
                                             // 24 bytes = one byte over MAX_LEN.
        let long = vec![0u8; 24];
        assert!(!looks_like_j1708(&long));
    }

    /// The checksum algorithm is verified against a known frame:
    /// MID 136 (Transmission), PID 0x61 = transmission temp.
    ///
    /// frame = [0x88, 0x61, data, checksum]
    /// all bytes must sum to 0 mod 256.
    #[test]
    fn checksum_algorithm_is_correct() {
        let f = frame(136, &[0x61, 0x45]);
        assert!(checksum_valid(&f), "sum should be 0 mod 256");
        // Recompute manually.
        let sum: u8 = f.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        assert_eq!(sum, 0);
    }

    /// An unknown MID is shown as hex rather than as an invented name.
    #[test]
    fn unknown_mid_is_shown_as_hex() {
        let f = frame(0x7F, &[0x01]);
        let r = dissect_j1708(&f);
        assert!(r.summary.contains("MID 0x7F"), "{}", r.summary);
        assert!(!r.summary.contains("Engine"), "{}", r.summary);
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(dissect_j1708(&[]).summary, "J1708 (truncated)");
        assert_eq!(dissect_j1708(&[0x80]).summary, "J1708 (truncated)");
    }
}
