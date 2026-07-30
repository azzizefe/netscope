// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// BSSAP splits into two sub-protocols behind a discriminator byte
/// (3GPP TS 48.006 §9.2): BSSMAP messages are between the base station
/// controller and the switch, while DTAP messages are simply relayed through —
/// they are really between the phone and the switch, with the base station in
/// the middle.
const DISCRIMINATOR_BSSMAP: u8 = 0x00;
const DISCRIMINATOR_DTAP: u8 = 0x01;

/// BSSMAP message types (3GPP TS 48.008 §3.2.2).
fn bssmap_name(t: u8) -> Option<&'static str> {
    Some(match t {
        0x01 => "ASSIGNMENT REQUEST",
        0x02 => "ASSIGNMENT COMPLETE",
        0x03 => "ASSIGNMENT FAILURE",
        0x10 => "HANDOVER REQUEST",
        0x11 => "HANDOVER REQUIRED",
        0x12 => "HANDOVER REQUEST ACKNOWLEDGE",
        0x13 => "HANDOVER COMMAND",
        0x14 => "HANDOVER COMPLETE",
        0x15 => "HANDOVER SUCCEEDED",
        0x16 => "HANDOVER FAILURE",
        0x17 => "HANDOVER PERFORMED",
        0x18 => "HANDOVER CANDIDATE ENQUIRE",
        0x19 => "HANDOVER CANDIDATE RESPONSE",
        0x1A => "HANDOVER REQUIRED REJECT",
        0x1B => "HANDOVER DETECT",
        0x20 => "CLEAR COMMAND",
        0x21 => "CLEAR COMPLETE",
        0x22 => "CLEAR REQUEST",
        0x25 => "SAPI N REJECT",
        0x26 => "CONFUSION",
        0x28 => "SUSPEND",
        0x29 => "RESUME",
        0x30 => "RESET",
        0x31 => "RESET ACKNOWLEDGE",
        0x32 => "OVERLOAD",
        0x34 => "RESET CIRCUIT",
        0x35 => "RESET CIRCUIT ACKNOWLEDGE",
        0x36 => "MSC INVOKE TRACE",
        0x37 => "BSS INVOKE TRACE",
        0x3A => "CONNECTIONLESS INFORMATION",
        0x40 => "BLOCK",
        0x41 => "BLOCKING ACKNOWLEDGE",
        0x42 => "UNBLOCK",
        0x43 => "UNBLOCKING ACKNOWLEDGE",
        0x44 => "CIRCUIT GROUP BLOCK",
        0x45 => "CIRCUIT GROUP BLOCKING ACKNOWLEDGE",
        0x46 => "CIRCUIT GROUP UNBLOCK",
        0x47 => "CIRCUIT GROUP UNBLOCKING ACKNOWLEDGE",
        0x48 => "UNEQUIPPED CIRCUIT",
        0x4E => "CHANGE CIRCUIT",
        0x4F => "CHANGE CIRCUIT ACKNOWLEDGE",
        0x50 => "RESOURCE REQUEST",
        0x51 => "RESOURCE INDICATION",
        0x52 => "PAGING",
        0x53 => "CIPHER MODE COMMAND",
        0x54 => "CLASSMARK UPDATE",
        0x55 => "CIPHER MODE COMPLETE",
        0x56 => "QUEUEING INDICATION",
        0x57 => "COMPLETE LAYER 3 INFORMATION",
        0x58 => "CLASSMARK REQUEST",
        0x59 => "CIPHER MODE REJECT",
        0x5A => "LOAD INDICATION",
        _ => return None,
    })
}

/// DTAP protocol discriminators (3GPP TS 24.007 §11.2.3.1.1) — the low nibble
/// of the first byte says which phone-to-network protocol the relayed message
/// belongs to.
fn dtap_protocol(discriminator: u8) -> &'static str {
    match discriminator & 0x0F {
        0x03 => "call control",
        0x05 => "mobility management",
        0x06 => "radio resources",
        0x08 => "GPRS mobility management",
        0x09 => "SMS",
        0x0A => "GPRS session management",
        0x0B => "non-call SS",
        _ => "message",
    }
}

/// Dissect a BSSAP message — the 2G interface between a base station controller
/// and the switch, carried inside SCCP at subsystem number 254 or 255
/// (3GPP TS 48.006).
pub fn dissect_bssap(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.first() {
        // BSSMAP: discriminator, length, then the message type.
        Some(&DISCRIMINATOR_BSSMAP) => match payload.get(2) {
            Some(&t) => match bssmap_name(t) {
                Some(name) => format!("BSSMAP {name}"),
                None => format!("BSSMAP message 0x{t:02x}"),
            },
            None => "BSSMAP (truncated)".to_string(),
        },
        // DTAP: discriminator, the link identifier, length, then the relayed
        // message, whose own first byte names its protocol.
        Some(&DISCRIMINATOR_DTAP) => match payload.get(3) {
            Some(&pd) => format!("BSSAP DTAP — {} (relayed to the phone)", dtap_protocol(pd)),
            None => "BSSAP DTAP (truncated)".to_string(),
        },
        Some(&other) => format!("BSSAP (unknown discriminator 0x{other:02x})"),
        None => "BSSAP (empty)".to_string(),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Bssap,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bssmap_paging() {
        let r = dissect_bssap(None, None, 1, 2, &[0x00, 0x08, 0x52, 0x00]);
        assert_eq!(r.protocol, Protocol::Bssap);
        assert_eq!(r.summary, "BSSMAP PAGING");
    }

    #[test]
    fn bssmap_cipher_mode_command() {
        let r = dissect_bssap(None, None, 1, 2, &[0x00, 0x04, 0x53]);
        assert_eq!(r.summary, "BSSMAP CIPHER MODE COMMAND");
    }

    /// DTAP is relayed rather than acted on by the base station, and its own
    /// first byte says which phone-to-network protocol it belongs to.
    #[test]
    fn dtap_names_the_relayed_protocol() {
        let r = dissect_bssap(None, None, 1, 2, &[0x01, 0x00, 0x03, 0x09]);
        assert_eq!(r.summary, "BSSAP DTAP — SMS (relayed to the phone)");
        let r = dissect_bssap(None, None, 1, 2, &[0x01, 0x00, 0x03, 0x05]);
        assert_eq!(
            r.summary,
            "BSSAP DTAP — mobility management (relayed to the phone)"
        );
    }

    #[test]
    fn unknown_bssmap_type_reports_its_byte() {
        let r = dissect_bssap(None, None, 1, 2, &[0x00, 0x04, 0x7E]);
        assert_eq!(r.summary, "BSSMAP message 0x7e");
    }

    #[test]
    fn truncated_and_empty_do_not_panic() {
        assert_eq!(
            dissect_bssap(None, None, 1, 2, &[]).summary,
            "BSSAP (empty)"
        );
        assert_eq!(
            dissect_bssap(None, None, 1, 2, &[0x00]).summary,
            "BSSMAP (truncated)"
        );
        assert_eq!(
            dissect_bssap(None, None, 1, 2, &[0x01, 0x00]).summary,
            "BSSAP DTAP (truncated)"
        );
        assert_eq!(
            dissect_bssap(None, None, 1, 2, &[0x7F]).summary,
            "BSSAP (unknown discriminator 0x7f)"
        );
    }
}
