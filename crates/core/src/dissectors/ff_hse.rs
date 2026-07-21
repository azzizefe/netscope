// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Foundation Fieldbus HSE — the Ethernet half of a process plant.
//!
//! A refinery or a chemical plant runs on instruments that never stop: a flow
//! transmitter publishing a reading a few times a second, a valve positioner
//! taking a setpoint, a controller closing the loop between them. Foundation
//! Fieldbus is the language, and HSE — High Speed Ethernet — is how the field
//! segments reach the control room.
//!
//! ## The service, not the service's success, is the diagnosis
//!
//! HSE messages carry a protocol identifier and a message type together in one
//! byte. The type is the part that matters: `request`, `response`, or **error**.
//! An error response to a `write` is a setpoint the plant believes it sent and
//! the device never applied — the operator's screen shows the new value because
//! the screen shows what was *requested*.
//!
//! The services divide into three worlds, and confusing them costs time:
//!
//! * **FMS** — the process data. `read`, `write`, `information report`. An
//!   information report is a device publishing on its own schedule; those
//!   stopping is a device that has gone quiet without disconnecting.
//! * **SM** — system management. `device annunciation` is a device announcing
//!   itself, and repeated annunciations from one address mean it keeps
//!   restarting.
//! * **FDA** — session management underneath both. `open session` and `idle`.
//!
//! ## The identifier and the type share a byte
//!
//! Protocol identifier is the top six bits, message type the low two. Reading
//! the whole byte turns every response and every error into an unrecognised
//! protocol, which loses exactly the messages worth seeing.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Version, options, protocol and type, service, address, length.
const HEADER: usize = 12;

/// Protocol identifiers, in the top six bits of byte 2.
const FDA: u8 = 0x04;
const SM: u8 = 0x08;
const FMS: u8 = 0x0C;
const LAN: u8 = 0x10;

fn protocol_name(id: u8) -> Option<&'static str> {
    Some(match id {
        FDA => "FDA",
        SM => "SM",
        FMS => "FMS",
        LAN => "LAN redundancy",
        _ => return None,
    })
}

/// The confirmed services of each protocol, which is where read and write live.
fn confirmed_service(protocol: u8, service: u8) -> Option<&'static str> {
    Some(match (protocol, service) {
        (FDA, 1) => "open session",
        (FDA, 3) => "idle",
        (SM, 3) => "identify",
        (SM, 12) => "clear address",
        (SM, 14) => "set assignment info",
        (SM, 15) => "clear assignment info",
        (FMS, 0) => "status",
        (FMS, 1) => "identify",
        (FMS, 2) => "read",
        (FMS, 3) => "write",
        (FMS, 4) => "get object dictionary",
        (FMS, 19) => "start",
        (FMS, 20) => "stop",
        (FMS, 21) => "resume",
        (FMS, 22) => "reset",
        (FMS, 23) => "kill",
        _ => return None,
    })
}

/// The unconfirmed services — the ones nobody answers, including the published
/// process data.
fn unconfirmed_service(protocol: u8, service: u8) -> Option<&'static str> {
    Some(match (protocol, service) {
        (SM, 1) => "find tag query",
        (SM, 2) => "find tag reply",
        (SM, 16) => "device annunciation",
        (FMS, 0) => "information report",
        (FMS, 1) => "unsolicited status",
        (FMS, 2) => "event notification",
        (FMS, 16) => "information report with subindex",
        (FMS, 17) => "information report on change",
        (FMS, 112) => "abort",
        _ => return None,
    })
}

/// Dissect a Foundation Fieldbus HSE message (ports 1089-1091, 3622).
pub fn dissect_ff_hse(
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
        protocol: Protocol::FfHse,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    let Some(head) = payload.get(..HEADER) else {
        return format!("FF HSE ({})", super::bytes(payload.len() as u64));
    };

    // The identifier is the top six bits and the message type the low two, in
    // one byte. Reading the byte whole loses every response and every error.
    let protocol = head[2] & 0xFC;
    let kind = head[2] & 0x03;
    let Some(protocol_name) = protocol_name(protocol) else {
        return format!("FF HSE (protocol {protocol:#04x})");
    };

    // The top bit of the service byte says whether anyone is expected to
    // answer, and the two service tables are different.
    let confirmed = head[3] & 0x80 != 0;
    let service_id = head[3] & 0x7F;
    let service = if confirmed {
        confirmed_service(protocol, service_id)
    } else {
        unconfirmed_service(protocol, service_id)
    }
    .map(str::to_string)
    .unwrap_or_else(|| format!("service {service_id}"));

    match kind {
        // An error to a write is a setpoint the plant thinks it applied.
        2 => format!("FF HSE {protocol_name} {service} — ERROR, the device refused it"),
        1 => format!("FF HSE {protocol_name} {service} response"),
        _ if confirmed => format!("FF HSE {protocol_name} {service} request"),
        // An unconfirmed message is published, not asked for.
        _ => format!("FF HSE {protocol_name} {service}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an HSE message header.
    fn hse(protocol: u8, kind: u8, confirmed: bool, service: u8) -> Vec<u8> {
        let mut v = vec![
            0x01, // version
            0x00, // options
            protocol | kind,
            if confirmed { 0x80 | service } else { service },
        ];
        v.extend_from_slice(&0u32.to_be_bytes()); // FDA address
        v.extend_from_slice(&(HEADER as u32).to_be_bytes()); // message length
        v
    }

    /// The reason this dissector exists: the operator's screen shows what was
    /// requested, so a refused write looks like a write that worked.
    #[test]
    fn a_refused_write_is_called_out() {
        let r = dissect_ff_hse(None, None, 40000, 1090, &hse(FMS, 2, true, 3));
        assert_eq!(r.protocol, Protocol::FfHse);
        assert_eq!(r.summary, "FF HSE FMS write — ERROR, the device refused it");
    }

    /// A request, a response and an error to the same service are three
    /// different facts about the plant.
    #[test]
    fn the_message_types_are_distinguished() {
        assert_eq!(describe(&hse(FMS, 0, true, 3)), "FF HSE FMS write request");
        assert_eq!(describe(&hse(FMS, 1, true, 3)), "FF HSE FMS write response");
        assert!(describe(&hse(FMS, 2, true, 3)).contains("ERROR"));
    }

    /// The identifier and the type share a byte. Reading it whole turns every
    /// response and error into an unknown protocol — losing the messages that
    /// matter most.
    #[test]
    fn the_identifier_and_type_share_a_byte() {
        for kind in 0..=2u8 {
            let summary = describe(&hse(FMS, kind, true, 2));
            assert!(summary.contains("FMS read"), "type {kind}: {summary}");
        }
    }

    /// The confirmed and unconfirmed tables assign different meanings to the
    /// same number, so the flag decides which one is read.
    #[test]
    fn the_confirmed_flag_selects_the_service_table() {
        // Service 2 is `read` when confirmed and `event notification` when not.
        assert!(describe(&hse(FMS, 0, true, 2)).contains("read"));
        assert!(describe(&hse(FMS, 0, false, 2)).contains("event notification"));
        // Service 1 is `identify` confirmed, `unsolicited status` unconfirmed.
        assert!(describe(&hse(FMS, 0, true, 1)).contains("identify"));
        assert!(describe(&hse(FMS, 0, false, 1)).contains("unsolicited status"));
    }

    /// Published process data is not a request and is not reported as one.
    #[test]
    fn an_information_report_is_not_a_request() {
        let summary = describe(&hse(FMS, 0, false, 0));
        assert_eq!(summary, "FF HSE FMS information report");
        assert!(!summary.contains("request"), "{summary}");
    }

    /// A device that keeps restarting announces itself repeatedly.
    #[test]
    fn a_device_annunciation_is_named() {
        assert!(describe(&hse(SM, 0, false, 16)).contains("device annunciation"));
    }

    #[test]
    fn the_three_protocols_are_named() {
        assert!(describe(&hse(FDA, 0, true, 1)).contains("FDA open session"));
        assert!(describe(&hse(SM, 0, true, 3)).contains("SM identify"));
        assert!(describe(&hse(LAN, 0, true, 1)).contains("LAN redundancy"));
    }

    #[test]
    fn an_unknown_service_reports_its_number() {
        assert!(describe(&hse(FMS, 0, true, 99)).contains("service 99"));
    }

    #[test]
    fn an_unknown_protocol_reports_its_identifier() {
        assert!(describe(&hse(0x40, 0, true, 1)).contains("protocol 0x40"));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "FF HSE (0 bytes)");
        assert_eq!(describe(&[0x01, 0x00, 0x0C]), "FF HSE (3 bytes)");
        assert_eq!(describe(&[0xFF; 11]), "FF HSE (11 bytes)");
    }
}
