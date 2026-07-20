// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The payload type whose body is a UDS message.
const PAYLOAD_DIAGNOSTIC: u16 = 0x8001;
/// Version, inverse, type and length make eight bytes; the source and target
/// ECU addresses another four. The UDS message starts after those.
const OFFSET_UDS: usize = 12;

/// Dissect a DoIP message (UDP/TCP 13400) — Diagnostics over IP, how a tester
/// reaches a vehicle's ECUs over Ethernet. Byte 0 is the version, bytes 2..4
/// the payload type (ISO 13400).
pub fn dissect_doip(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        let ptype = u16::from_be_bytes([payload[2], payload[3]]);
        // A diagnostic message is only the envelope. The letter inside is UDS,
        // and it is what separates reading a fault code from reflashing an ECU
        // — otherwise every one of them reads the same.
        if ptype == PAYLOAD_DIAGNOSTIC {
            if let Some(uds) = payload.get(OFFSET_UDS..).and_then(super::uds::describe) {
                return DissectedResult {
                    src_addr: src_ip,
                    dst_addr: dst_ip,
                    src_port: Some(src_port),
                    dst_port: Some(dst_port),
                    protocol: Protocol::Uds,
                    summary: uds,
                };
            }
        }
        let name = match ptype {
            0x0000 => "Generic negative ack",
            0x0001 => "Vehicle ID request",
            0x0004 => "Vehicle announcement",
            0x0005 => "Routing activation request",
            0x0006 => "Routing activation response",
            0x0007 => "Alive check request",
            0x8001 => "Diagnostic message",
            0x8002 => "Diagnostic ack",
            0x8003 => "Diagnostic nack",
            _ => "message",
        };
        format!("DoIP {name}")
    } else {
        "DoIP (truncated)".to_string()
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Doip,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a diagnostic message carrying the given UDS payload.
    fn diagnostic(uds: &[u8]) -> Vec<u8> {
        let mut p = vec![0x02, 0xFD, 0x80, 0x01];
        p.extend_from_slice(&((uds.len() + 4) as u32).to_be_bytes());
        p.extend_from_slice(&0x0E00u16.to_be_bytes()); // source ECU
        p.extend_from_slice(&0x0001u16.to_be_bytes()); // target ECU
        p.extend_from_slice(uds);
        p
    }

    #[test]
    fn diagnostic_message() {
        // version 0x02, inverse 0xFD, payload type 0x8001.
        let r = dissect_doip(None, None, 40000, 13400, &[0x02, 0xFD, 0x80, 0x01]);
        assert_eq!(r.protocol, Protocol::Doip);
        assert_eq!(r.summary, "DoIP Diagnostic message");
    }

    /// The envelope is the same for every diagnostic message, so without
    /// reading the UDS inside, unlocking an ECU and reading a fault code look
    /// identical in a capture.
    #[test]
    fn the_uds_inside_is_read_rather_than_the_envelope_named() {
        let r = dissect_doip(None, None, 40000, 13400, &diagnostic(&[0x22, 0xF1, 0x90]));
        assert_eq!(r.protocol, Protocol::Uds);
        assert_eq!(r.summary, "UDS read data 0xF190");

        let r = dissect_doip(None, None, 40000, 13400, &diagnostic(&[0x27, 0x01]));
        assert_eq!(r.summary, "UDS security access — seed request");

        let r = dissect_doip(None, None, 13400, 1, &diagnostic(&[0x7F, 0x27, 0x35]));
        assert_eq!(r.summary, "UDS security access refused — invalid key");
    }

    /// A manufacturer-specific service has no standard name, so the envelope is
    /// named rather than a verb invented for it.
    #[test]
    fn an_unreadable_body_falls_back_to_the_envelope() {
        let r = dissect_doip(None, None, 40000, 13400, &diagnostic(&[0xBA, 0x01]));
        assert_eq!(r.protocol, Protocol::Doip);
        assert_eq!(r.summary, "DoIP Diagnostic message");
    }

    /// A diagnostic message with nothing after the addresses must not panic or
    /// claim to have read anything.
    #[test]
    fn a_bodyless_diagnostic_message_stays_doip() {
        let r = dissect_doip(None, None, 40000, 13400, &diagnostic(&[]));
        assert_eq!(r.protocol, Protocol::Doip);
    }
}
