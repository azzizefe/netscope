// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! M-Bus — how utility meters are read (EN 13757).
//!
//! A block of flats has one gateway polling every water, gas, heat and
//! electricity meter in the building, and this is what that conversation looks
//! like once it has been put on TCP. It is worth reading because a meter that
//! has stopped answering is invisible otherwise: the gateway keeps asking, the
//! billing system keeps showing the last value it got, and nothing looks wrong
//! until an estimated bill arrives.
//!
//! The framing is unambiguous — a start byte, a repeated length, and a fixed
//! stop byte — which is what makes it safe to recognise on content.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// A frame carrying a length and data.
const START_LONG: u8 = 0x68;
/// A frame with a fixed layout and no data.
const START_SHORT: u8 = 0x10;
/// Every frame ends with this.
const STOP: u8 = 0x16;
/// A bare acknowledgement is a single byte with no framing at all.
const SINGLE_ACK: u8 = 0xE5;

/// Addresses with a meaning other than "one meter".
const ADDRESS_NETWORK: u8 = 253;
const ADDRESS_BROADCAST_REPLY: u8 = 254;
const ADDRESS_BROADCAST_SILENT: u8 = 255;

/// What the primary address refers to.
fn address_name(address: u8) -> String {
    match address {
        ADDRESS_NETWORK => "network layer".to_string(),
        ADDRESS_BROADCAST_REPLY => "all meters".to_string(),
        ADDRESS_BROADCAST_SILENT => "all meters (no reply)".to_string(),
        other => format!("meter {other}"),
    }
}

/// The control field says what is being asked. The direction bit distinguishes
/// a master's request from a meter's reply, and the frame-count bit toggles
/// between retries, so both are masked off before matching.
fn control_name(control: u8) -> Option<&'static str> {
    Some(match control & 0x0F {
        0x0 if control & 0x40 != 0 => "initialise",
        0x0 => "acknowledge",
        0x3 => "send data",
        0x4 => "send data (no reply)",
        0x8 => "reply",
        0xA => "request status",
        0xB => "request data",
        _ => return None,
    })
}

/// What a meter measures. Read from the fixed header of a variable-data reply,
/// and the most useful single fact in the protocol: it says what the device
/// actually is.
fn medium_name(medium: u8) -> Option<&'static str> {
    Some(match medium {
        0x00 => "other",
        0x01 => "oil meter",
        0x02 => "electricity meter",
        0x03 => "gas meter",
        0x04 => "heat meter",
        0x05 => "steam meter",
        0x06 => "hot water meter",
        0x07 => "water meter",
        0x08 => "heat cost allocator",
        0x09 => "compressed air meter",
        0x0A | 0x0B => "cooling meter",
        0x0C | 0x0D => "heat meter (combined)",
        0x0E => "bus/system component",
        0x15 => "hot water meter (cold/hot)",
        0x16 => "cold water meter",
        0x17 => "dual water meter",
        0x18 => "pressure meter",
        0x19 => "A/D converter",
        _ => return None,
    })
}

/// The application layer's first byte, which says what kind of reply follows.
const CI_VARIABLE_DATA: u8 = 0x72;

/// Whether a payload is an M-Bus frame.
///
/// The start byte, the repeated length and the stop byte have to agree, which
/// no other protocol's traffic does by accident.
pub(crate) fn looks_like_mbus(payload: &[u8]) -> bool {
    match payload.first() {
        Some(&SINGLE_ACK) => payload.len() == 1,
        Some(&START_SHORT) => payload.len() >= 5 && payload[4] == STOP,
        Some(&START_LONG) => long_frame_len(payload).is_some(),
        _ => false,
    }
}

/// The body length of a long frame, if its framing is self-consistent.
fn long_frame_len(payload: &[u8]) -> Option<usize> {
    let len = *payload.get(1)? as usize;
    // The length is sent twice and the start byte repeated, which is the check
    // that makes this safe to identify on content.
    if payload.get(2)? != &(len as u8) || payload.get(3)? != &START_LONG {
        return None;
    }
    // Start, length, length, start, then the body, then checksum and stop.
    let total = 4 + len + 2;
    if payload.get(total - 1)? != &STOP {
        return None;
    }
    Some(len)
}

/// The meter's serial number and what it measures, from a variable-data reply.
///
/// The identification is eight binary-coded decimal digits, stored little-end
/// first — reading them as an ordinary integer gives a number that looks
/// plausible and is wrong.
fn identify(body: &[u8]) -> Option<(String, u8)> {
    // Control, address, then the application layer's first byte.
    if body.get(2)? != &CI_VARIABLE_DATA {
        return None;
    }
    let id = body.get(3..7)?;
    let serial = format!("{:02X}{:02X}{:02X}{:02X}", id[3], id[2], id[1], id[0]);
    // Manufacturer (2) and version (1) sit between the identification and the
    // medium.
    let medium = *body.get(10)?;
    Some((serial, medium))
}

/// Dissect an M-Bus frame.
pub fn dissect_mbus(
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
        protocol: Protocol::MBus,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    match payload.first() {
        Some(&SINGLE_ACK) => "M-Bus acknowledgement".to_string(),
        Some(&START_SHORT) if payload.len() >= 5 => {
            let control = payload[1];
            let address = payload[2];
            let what = control_name(control).unwrap_or("request");
            format!("M-Bus {what} — {}", address_name(address))
        }
        Some(&START_LONG) => {
            let Some(len) = long_frame_len(payload) else {
                return format!("M-Bus frame ({})", super::bytes(payload.len() as u64));
            };
            let Some(body) = payload.get(4..4 + len) else {
                return format!("M-Bus frame ({})", super::bytes(payload.len() as u64));
            };
            let control = body.first().copied().unwrap_or(0);
            let address = body.get(1).copied().unwrap_or(0);
            let what = control_name(control).unwrap_or("frame");

            // A reply that carries the meter's identity is the useful one: it
            // says what the device is, not just that something answered.
            match identify(body) {
                Some((serial, medium)) => match medium_name(medium) {
                    Some(kind) => format!("M-Bus reply — {kind}, serial {serial}"),
                    None => format!("M-Bus reply — serial {serial}"),
                },
                None => format!("M-Bus {what} — {}", address_name(address)),
            }
        }
        _ => format!("M-Bus ({})", super::bytes(payload.len() as u64)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a long frame around the given body.
    fn long(body: &[u8]) -> Vec<u8> {
        let mut p = vec![START_LONG, body.len() as u8, body.len() as u8, START_LONG];
        p.extend_from_slice(body);
        let checksum = body.iter().fold(0u8, |a, b| a.wrapping_add(*b));
        p.push(checksum);
        p.push(STOP);
        p
    }

    /// A variable-data reply body: control, address, CI, then the fixed header.
    fn reply(serial: [u8; 4], medium: u8) -> Vec<u8> {
        let mut b = vec![0x08, 0x01, CI_VARIABLE_DATA];
        b.extend_from_slice(&serial);
        b.extend_from_slice(&[0x24, 0x23]); // manufacturer
        b.push(0x01); // version
        b.push(medium);
        b.extend_from_slice(&[0x00, 0x00, 0x00]); // access, status, signature
        b
    }

    /// The most useful thing in the protocol: what the device actually is.
    #[test]
    fn a_reply_says_what_kind_of_meter_answered() {
        // Serial 12345678, stored little-end first.
        let frame = long(&reply([0x78, 0x56, 0x34, 0x12], 0x07));
        let r = dissect_mbus(None, None, 40000, 10001, &frame);
        assert_eq!(r.protocol, Protocol::MBus);
        assert_eq!(r.summary, "M-Bus reply — water meter, serial 12345678");
    }

    /// A building has several kinds of meter on one bus, and telling them apart
    /// is the whole point of reading the medium byte.
    #[test]
    fn each_medium_is_named() {
        for (medium, expected) in [
            (0x02u8, "electricity meter"),
            (0x03, "gas meter"),
            (0x04, "heat meter"),
            (0x06, "hot water meter"),
            (0x16, "cold water meter"),
        ] {
            let frame = long(&reply([0x01, 0x00, 0x00, 0x00], medium));
            let summary = dissect_mbus(None, None, 1, 10001, &frame).summary;
            assert!(summary.contains(expected), "{medium:#04x}: {summary}");
        }
    }

    /// The serial is binary-coded decimal stored little-end first. Reading it
    /// as an ordinary integer produces a plausible, wrong number.
    #[test]
    fn the_serial_is_read_least_significant_byte_first() {
        let frame = long(&reply([0x01, 0x00, 0x00, 0x00], 0x07));
        let summary = dissect_mbus(None, None, 1, 10001, &frame).summary;
        assert!(summary.contains("serial 00000001"), "{summary}");
        assert!(
            !summary.contains("serial 01000000"),
            "read the bytes backwards"
        );
    }

    /// The gateway's side of the conversation: asking a specific meter to
    /// report.
    #[test]
    fn a_request_names_the_meter_it_is_addressed_to() {
        let frame = [START_SHORT, 0x5B, 0x0A, 0x65, STOP];
        assert_eq!(
            dissect_mbus(None, None, 1, 10001, &frame).summary,
            "M-Bus request data — meter 10"
        );
    }

    /// Broadcast addresses do not name one meter, and saying "meter 254" would
    /// be wrong.
    #[test]
    fn broadcast_addresses_are_named_as_such() {
        let frame = [START_SHORT, 0x53, ADDRESS_BROADCAST_REPLY, 0x00, STOP];
        assert!(dissect_mbus(None, None, 1, 10001, &frame)
            .summary
            .contains("all meters"));
        let frame = [START_SHORT, 0x53, ADDRESS_NETWORK, 0x00, STOP];
        assert!(dissect_mbus(None, None, 1, 10001, &frame)
            .summary
            .contains("network layer"));
    }

    /// The shortest possible frame is one byte with no framing, which still has
    /// to be recognised rather than treated as a truncated long frame.
    #[test]
    fn a_bare_acknowledgement_is_recognised() {
        assert!(looks_like_mbus(&[SINGLE_ACK]));
        assert_eq!(
            dissect_mbus(None, None, 1, 10001, &[SINGLE_ACK]).summary,
            "M-Bus acknowledgement"
        );
        // Only on its own — the same byte inside other traffic means nothing.
        assert!(!looks_like_mbus(&[SINGLE_ACK, 0x00]));
    }

    /// The repeated length and the stop byte are what make recognition safe.
    #[test]
    fn inconsistent_framing_is_not_claimed() {
        assert!(looks_like_mbus(&long(&[0x08, 0x01, 0x72])));

        // The two length bytes disagree.
        let mut bad = long(&[0x08, 0x01, 0x72]);
        bad[2] = 0xFF;
        assert!(!looks_like_mbus(&bad));

        // The stop byte is missing.
        let mut bad = long(&[0x08, 0x01, 0x72]);
        let last = bad.len() - 1;
        bad[last] = 0x00;
        assert!(!looks_like_mbus(&bad));

        assert!(!looks_like_mbus(b"GET / HTTP/1.1\r\n\r\n"));
        assert!(!looks_like_mbus(&[]));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert!(dissect_mbus(None, None, 1, 10001, &[START_LONG, 0x20])
            .summary
            .starts_with("M-Bus"));
        assert!(dissect_mbus(None, None, 1, 10001, &[])
            .summary
            .starts_with("M-Bus"));
    }
}
