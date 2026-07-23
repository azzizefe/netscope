// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Wireless M-Bus — the radio link layer for smart meters (EN 13757-4).
//!
//! A concentrator collects readings from hundreds of wireless water, gas, heat
//! and electricity meters and forwards them onto IP, and this is what those
//! frames look like once the radio preamble has been removed. It shares its
//! application layer with wired M-Bus (EN 13757-3), so the CI-field names are
//! the same, but the framing is different: no 0x68/0x10 start byte and no
//! 0x16 stop byte, just a repeated length field followed by the payload.
//!
//! Three modes cover most real-world traffic:
//!
//! - **S mode** (868.3 MHz, stationary): the meter reports once every few
//!   minutes; this is the common one in fixed residential metering.
//! - **T mode** (868.95 MHz, frequent transmit): the meter sends every few
//!   seconds — battery-powered but short-lived.
//! - **C mode** (868.95 MHz, compact): short frames of 8 data bytes or fewer,
//!   used when a few values need to leave the meter in a tight window.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The C-field (control) direction bit — set when the meter sends a reply.
const DIR_METER_TO_MASTER: u8 = 0x40;
/// Spare bit in S mode, FCB in T/C mode — toggled by the sender on each
/// transmission so the receiver can tell a retry from a new message.
const _FCB: u8 = 0x20;

/// Application-layer CI-field values, shared with wired M-Bus.
fn ci_name(ci: u8) -> Option<&'static str> {
    Some(match ci {
        0x51 => "data send",
        0x52 => "selection",
        0x5A => "warm start",
        0x60 => "COSEM transport (EN 62056-21)",
        0x61 => "COSEM security (DLMS/COSEM)",
        0x6C => "time sync",
        0x6D => "alarm",
        0x6E => "firmware",
        0x70 => "application reset",
        0x71 => "application reset (subcode)",
        0x72 => "variable data reply",
        0x73 => "fixed data reply",
        0x78 => "set baud rate",
        0x7A => "set baud rate reply",
        0x80..=0x8F => "manufacturer-specific",
        0xA0 => "M-Bus authentication (OMS)",
        0xA1 => "M-Bus key exchange (OMS)",
        0xB0 => "COSEM wrapper",
        0xB1 => "COSEM wrapper encrypted",
        _ => return None,
    })
}

/// The C-field function code, masked of direction, FCB and FCV.
fn control_name(control: u8) -> Option<&'static str> {
    Some(match control & 0x0F {
        0x0 => "initialise",
        0x3 => "send data",
        0x4 => "send data (no reply)",
        0x8 => "reply",
        0x9 => "reply (retry)",
        0xA => "request status",
        0xB => "request data",
        0xC => "request data (retry)",
        _ => return None,
    })
}

/// Which mode a wM-Bus frame belongs to, inferred from the C-field and length.
fn mode_name(c_field: u8, data_len: usize) -> &'static str {
    // C mode is compact — ≤8 data bytes and the C-field uses a different
    // encoding (battery life in the high nibble).
    if data_len <= 8 {
        return "C";
    }
    // T mode: frequent transmit, identified by bit 2 being set in S/T
    // differentiation (the access-demanded flag in T mode framing).
    if c_field & 0x04 != 0 {
        return "T";
    }
    // S mode is the default — stationary / residential.
    "S"
}

/// The CI-field position within the `data` slice (payload[4..]), which starts
/// at the second byte of the M-field in S/T modes, or at the CI-field in C mode.
fn ci_position(mode: &str, data: &[u8]) -> Option<usize> {
    match mode {
        // C mode: C(1) + A(1) before data → CI is the first byte of data.
        "C" => (!data.is_empty()).then_some(0),
        // T mode with 2-byte A: M(1) + A(2) = 3 bytes before CI.
        "T" => {
            if data.len() >= 4 && data.get(3).is_some_and(|b| ci_name(*b).is_some()) {
                return Some(3);
            }
            // T mode with 4-byte A: M(1) + A(4) = 5 bytes before CI.
            (data.len() >= 6).then_some(5)
        }
        // S mode: M(1) + A(4) = 5 bytes before CI.
        _ => (data.len() >= 6).then_some(5),
    }
}

/// Extract the address (A-field) bytes from the data slice. In S/T modes the
/// A-field starts after the one remaining M-field byte; in C mode the A-field
/// sits before the data slice and cannot be returned.
fn address_bytes<'a>(mode: &str, data: &'a [u8]) -> Option<&'a [u8]> {
    match mode {
        "C" => None,
        "T" => {
            if data.len() >= 4 && data.get(3).is_some_and(|b| ci_name(*b).is_some()) {
                data.get(1..3) // 2-byte address
            } else {
                data.get(1..5) // 4-byte address
            }
        }
        _ => data.get(1..5), // S mode: 4-byte address
    }
}

/// Address encoding in wM-Bus: the A-field carries the meter's serial number
/// in BCD, little-end first (same convention as wired M-Bus).
fn address_serial(a_field: &[u8]) -> String {
    a_field
        .iter()
        .rev()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join("")
        .trim_start_matches('0')
        .to_string()
}

/// Whether a payload is plausibly a wM-Bus frame (without the radio preamble).
///
/// The first two bytes must be identical and the length they encode must fit
/// the remaining payload — this is the same self-consistency check that makes
/// M-Bus recognition safe, adapted for the radio frame format.
pub(crate) fn looks_like_wmbus(payload: &[u8]) -> bool {
    frame_len(payload).is_some()
}

/// If the payload is a well-formed wM-Bus frame, return the number of bytes
/// from the start of the L-field through the end of the data (excludes the
/// optional CRC, which gateways may or may not forward).
fn frame_len(payload: &[u8]) -> Option<usize> {
    if payload.len() < 4 {
        return None;
    }
    // The length field is repeated — they must agree.
    let l = payload[0] as usize;
    if payload[1] != payload[0] {
        return None;
    }
    // The C-field must be in a reasonable range.
    let c = payload[2];
    if !valid_c_field(c) {
        return None;
    }
    // Two L-fields, then `l` bytes of payload. After that there may be a
    // 2-byte CRC that the gateway may or may not have forwarded.
    let frame_body = 2 + l;
    if payload.len() < frame_body {
        return None;
    }
    Some(frame_body)
}

/// The C-field's lower nibble is the function, which must be a recognised
/// code, and the upper nibble must be plausible (direction + FCB + FCV).
fn valid_c_field(c: u8) -> bool {
    matches!(
        c & 0x0F,
        0x0 | 0x3 | 0x4 | 0x8 | 0x9 | 0xA | 0xB | 0xC
    )
}

/// Dissect a wM-Bus frame that has had its radio preamble removed.
pub fn dissect_wmbus(
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
        protocol: Protocol::Wmbus,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    let Some(body_len) = frame_len(payload) else {
        return format!("wM-Bus frame ({})", super::bytes(payload.len() as u64));
    };

    let l = payload[0] as usize;
    let c = payload[2];
    let data = payload.get(4..body_len).unwrap_or(&[]);

    // l is the body length (C + M + A + CI + payload), which must be at least
    // 2 for a valid frame — but malformed fuzz input can still reach here.
    let mode = mode_name(c, l.saturating_sub(2));
    let ctrl = control_name(c).unwrap_or("frame");

    // Build a summary that names the mode, the function, and (for replies)
    // the meter — the same depth wired M-Bus achieves.
    if ctrl == "reply" || ctrl == "reply (retry)" {
        if let Some(ci_pos) = ci_position(mode, data) {
            if let Some(&ci) = data.get(ci_pos) {
                if let Some(ci_label) = ci_name(ci) {
                    if let Some(addr) = address_bytes(mode, data) {
                        let serial = address_serial(addr);
                        if !serial.is_empty() {
                            return format!(
                                "wM-Bus ({mode}) reply — {ci_label}, serial {serial}"
                            );
                        }
                    }
                    return format!("wM-Bus ({mode}) reply — {ci_label}");
                }
            }
        }
        return format!("wM-Bus ({mode}) {ctrl}");
    }

    // For requests and data-send frames, include direction.
    let from = if c & DIR_METER_TO_MASTER != 0 {
        "from meter"
    } else {
        "to meter"
    };
    format!("wM-Bus ({mode}) {ctrl} {from}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a wM-Bus S-mode frame: two identical L bytes, then the body.
    fn s_frame(c_field: u8, m_field: [u8; 2], a_field: &[u8], ci: u8, data: &[u8]) -> Vec<u8> {
        let body_len = 1 + 2 + a_field.len() + 1 + data.len(); // C + M + A + CI + data
        let l = body_len as u8;
        let mut p = vec![l, l, c_field];
        p.extend_from_slice(&m_field);
        p.extend_from_slice(a_field);
        p.push(ci);
        p.extend_from_slice(data);
        p
    }

    #[test]
    fn a_reply_names_the_mode_ci_and_meter() {
        let frame = s_frame(0x08, [0x12, 0x34], &[0x56, 0x78, 0x90, 0x12], 0x72, b"hello");
        let r = dissect_wmbus(None, None, 10001, 50000, &frame);
        assert_eq!(r.protocol, Protocol::Wmbus);
        assert!(
            r.summary.contains("wM-Bus (S) reply — variable data reply"),
            "{}",
            r.summary
        );
        // Serial is BCD, LE: 0x12, 0x90, 0x78, 0x56 → "12907856"
        assert!(r.summary.contains("serial 12907856"), "{}", r.summary);
    }

    #[test]
    fn a_data_request_includes_direction() {
        // Request data from master to meter: direction bit clear, FCV set.
        let frame = s_frame(0x1B, [0x00, 0x00], &[0x01, 0x00, 0x00, 0x00], 0x00, &[]);
        let summary = dissect_wmbus(None, None, 10001, 50000, &frame).summary;
        assert!(summary.contains("request data to meter"));
    }

    #[test]
    fn inconsistent_length_is_rejected() {
        let mut frame = s_frame(0x08, [0x12, 0x34], &[0x56; 4], 0x72, &[]);
        // Break the repeated length.
        frame[1] = frame[0].wrapping_add(1);
        assert!(!looks_like_wmbus(&frame));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert!(
            dissect_wmbus(None, None, 10001, 50000, &[5, 5, 0x08])
                .summary
                .starts_with("wM-Bus"));
        assert!(
            dissect_wmbus(None, None, 10001, 50000, &[])
                .summary
                .starts_with("wM-Bus"));
    }

    #[test]
    fn bogus_c_field_is_not_claimed() {
        // 0x0F is not a valid function code.
        let frame = s_frame(0x0F, [0x00, 0x00], &[0x00; 4], 0x00, &[]);
        assert!(!looks_like_wmbus(&frame));
    }

    #[test]
    fn normal_traffic_does_not_false_trigger() {
        assert!(!looks_like_wmbus(b"GET / HTTP/1.1\r\n\r\n"));
        assert!(!looks_like_wmbus(b"\x16\x03\x01\x00\x00"));
        assert!(!looks_like_wmbus(&[]));
    }
}
