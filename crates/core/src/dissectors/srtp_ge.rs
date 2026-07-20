// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! GE-SRTP — the protocol GE Fanuc / Emerson PLCs speak on TCP 18245.
//!
//! Unlike the other industrial protocols here, GE-SRTP has no published
//! specification; what is known comes from reverse engineering. This dissector
//! therefore stays deliberately shallow. It reports the two fields that are
//! well established — the message type in the first byte and the service
//! request code at offset 42 of the 56-byte header — and does not attempt to
//! decode the request body, because guessing at undocumented offsets would
//! produce confident-looking output that is simply wrong.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The fixed header length. A message shorter than this cannot carry a service
/// request code.
const HEADER: usize = 56;
/// Where the service request code sits within that header.
const SERVICE_CODE_OFFSET: usize = 42;

/// Message types seen in the first byte.
fn message_type(t: u8) -> Option<&'static str> {
    Some(match t {
        0x02 => "request",
        0x03 => "response",
        _ => return None,
    })
}

/// Service request codes. Only the codes that are consistently documented
/// across independent reverse-engineering write-ups are named here.
fn service_name(code: u8) -> Option<&'static str> {
    Some(match code {
        0x00 => "PLC Short Status",
        0x03 => "Read System Memory",
        0x04 => "Read Task Memory",
        0x05 => "Read Program Block Memory",
        0x07 => "Write System Memory",
        0x08 => "Write Task Memory",
        0x09 => "Write Program Block Memory",
        0x0F => "Read SMEM/Program Name",
        0x20 => "Return Controller Type and ID",
        0x21 => "Return PLC Time/Date",
        0x22 => "Return Fault Table",
        0x23 => "Clear Fault Table",
        0x24 => "Programmer Logon",
        0x25 => "Change PLC Privilege Level",
        0x43 => "Set Control Program Number",
        _ => return None,
    })
}

/// Dissect a GE-SRTP message (TCP 18245).
pub fn dissect_srtp_ge(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match parse(payload) {
        Some(s) => s,
        None => format!("GE-SRTP ({})", super::bytes(payload.len() as u64)),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SrtpGe,
        summary,
    }
}

fn parse(payload: &[u8]) -> Option<String> {
    if payload.len() < HEADER {
        return None;
    }
    let direction = message_type(payload[0])?;
    let code = payload[SERVICE_CODE_OFFSET];
    Some(match service_name(code) {
        Some(name) => format!("GE-SRTP {name} ({direction})"),
        None => format!("GE-SRTP service 0x{code:02x} ({direction})"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a 56-byte header with the given type and service code.
    fn srtp(msg_type: u8, code: u8) -> Vec<u8> {
        let mut p = vec![0u8; HEADER];
        p[0] = msg_type;
        p[SERVICE_CODE_OFFSET] = code;
        p
    }

    #[test]
    fn read_system_memory_request() {
        let r = dissect_srtp_ge(None, None, 40000, 18245, &srtp(0x02, 0x03));
        assert_eq!(r.protocol, Protocol::SrtpGe);
        assert_eq!(r.summary, "GE-SRTP Read System Memory (request)");
    }

    #[test]
    fn response_direction_is_reported() {
        let r = dissect_srtp_ge(None, None, 18245, 40000, &srtp(0x03, 0x00));
        assert_eq!(r.summary, "GE-SRTP PLC Short Status (response)");
    }

    /// The write and privilege services are the ones that change plant state.
    #[test]
    fn write_and_privilege_services_are_named() {
        let r = dissect_srtp_ge(None, None, 1, 18245, &srtp(0x02, 0x07));
        assert_eq!(r.summary, "GE-SRTP Write System Memory (request)");
        let r = dissect_srtp_ge(None, None, 1, 18245, &srtp(0x02, 0x25));
        assert_eq!(r.summary, "GE-SRTP Change PLC Privilege Level (request)");
    }

    /// The code list is deliberately partial, so an unnamed code has to report
    /// its number rather than be dropped.
    #[test]
    fn undocumented_service_reports_its_code() {
        let r = dissect_srtp_ge(None, None, 1, 18245, &srtp(0x02, 0x7E));
        assert_eq!(r.summary, "GE-SRTP service 0x7e (request)");
    }

    /// An unrecognised first byte means this is not GE-SRTP; claiming it would
    /// mislabel whatever else is on the port.
    #[test]
    fn foreign_message_type_is_not_claimed() {
        let r = dissect_srtp_ge(None, None, 1, 18245, &srtp(0x47, 0x03));
        assert_eq!(r.summary, "GE-SRTP (56 bytes)");
    }

    #[test]
    fn short_message_does_not_panic() {
        let r = dissect_srtp_ge(None, None, 1, 18245, &[0x02, 0x00, 0x00]);
        assert_eq!(r.summary, "GE-SRTP (3 bytes)");
    }
}
