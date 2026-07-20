// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// FINS command codes, as a two-byte pair (Omron FINS command reference W227).
/// The high byte groups the command, the low byte selects within the group.
fn command_name(mr: u8, sr: u8) -> Option<&'static str> {
    Some(match (mr, sr) {
        (0x01, 0x01) => "MEMORY AREA READ",
        (0x01, 0x02) => "MEMORY AREA WRITE",
        (0x01, 0x03) => "MEMORY AREA FILL",
        (0x01, 0x04) => "MULTIPLE MEMORY AREA READ",
        (0x01, 0x05) => "MEMORY AREA TRANSFER",
        (0x02, 0x01) => "PARAMETER AREA READ",
        (0x02, 0x02) => "PARAMETER AREA WRITE",
        (0x02, 0x03) => "PARAMETER AREA CLEAR",
        (0x03, 0x06) => "PROGRAM AREA READ",
        (0x03, 0x07) => "PROGRAM AREA WRITE",
        (0x03, 0x08) => "PROGRAM AREA CLEAR",
        (0x04, 0x01) => "RUN",
        (0x04, 0x02) => "STOP",
        (0x05, 0x01) => "CPU UNIT DATA READ",
        (0x05, 0x02) => "CONNECTION DATA READ",
        (0x06, 0x01) => "CPU UNIT STATUS READ",
        (0x06, 0x20) => "CYCLE TIME READ",
        (0x07, 0x01) => "CLOCK READ",
        (0x07, 0x02) => "CLOCK WRITE",
        (0x09, 0x20) => "MESSAGE READ/CLEAR",
        (0x0C, 0x01) => "ACCESS RIGHT ACQUIRE",
        (0x0C, 0x02) => "ACCESS RIGHT FORCED ACQUIRE",
        (0x0C, 0x03) => "ACCESS RIGHT RELEASE",
        (0x21, 0x01) => "ERROR CLEAR",
        (0x21, 0x02) => "ERROR LOG READ",
        (0x21, 0x03) => "ERROR LOG CLEAR",
        (0x22, 0x01) => "FILE NAME READ",
        (0x22, 0x02) => "SINGLE FILE READ",
        (0x22, 0x03) => "SINGLE FILE WRITE",
        (0x23, 0x01) => "FORCED SET/RESET",
        (0x23, 0x02) => "FORCED SET/RESET CANCEL",
        _ => return None,
    })
}

/// The fixed FINS header (Omron W227 §5-1): information control field, reserve,
/// gateway count, then destination and source network/node/unit triples, then a
/// service id — ten bytes before the command code.
const HEADER: usize = 10;

/// Bit 6 of the information control field is set on a response.
const ICF_RESPONSE: u8 = 0x40;

/// Dissect a FINS message — Omron's factory-automation protocol for talking to
/// PLCs, on UDP or TCP 9600 (Omron FINS command reference W227).
///
/// FINS is unauthenticated by design: a MEMORY AREA WRITE or a STOP command is
/// accepted from anyone who can reach the PLC, which is why seeing these on a
/// network worth capturing is itself notable.
pub fn dissect_fins(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < HEADER + 2 {
        format!("FINS ({})", super::bytes(payload.len() as u64))
    } else {
        let is_response = payload[0] & ICF_RESPONSE != 0;
        // Destination network / node / unit — which PLC on which network.
        let (dna, da1) = (payload[3], payload[4]);
        let (mr, sr) = (payload[HEADER], payload[HEADER + 1]);
        let direction = if is_response { "response" } else { "command" };
        match command_name(mr, sr) {
            Some(name) => format!("FINS {name} ({direction}) — node {dna}.{da1}"),
            None => format!("FINS command {mr:02x}{sr:02x} ({direction}) — node {dna}.{da1}"),
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Fins,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a FINS frame: ICF, RSV, GCT, DNA, DA1, DA2, SNA, SA1, SA2, SID,
    /// then the two command bytes.
    fn fins(response: bool, dna: u8, da1: u8, mr: u8, sr: u8) -> Vec<u8> {
        let icf = if response { 0xC0 } else { 0x80 };
        vec![
            icf, 0x00, 0x02, dna, da1, 0x00, 0x00, 0x01, 0x00, 0x00, mr, sr,
        ]
    }

    #[test]
    fn memory_area_read_command() {
        let p = fins(false, 1, 20, 0x01, 0x01);
        let r = dissect_fins(None, None, 40000, 9600, &p);
        assert_eq!(r.protocol, Protocol::Fins);
        assert_eq!(r.summary, "FINS MEMORY AREA READ (command) — node 1.20");
    }

    /// The response bit lives in the information control field; reading it
    /// wrongly would label every answer as a fresh command.
    #[test]
    fn response_bit_is_read_from_the_control_field() {
        let p = fins(true, 1, 20, 0x01, 0x01);
        let r = dissect_fins(None, None, 9600, 40000, &p);
        assert_eq!(r.summary, "FINS MEMORY AREA READ (response) — node 1.20");
    }

    /// Commands that change plant state are the ones worth spotting.
    #[test]
    fn run_and_stop_are_named() {
        let r = dissect_fins(None, None, 1, 9600, &fins(false, 0, 5, 0x04, 0x02));
        assert_eq!(r.summary, "FINS STOP (command) — node 0.5");
        let r = dissect_fins(None, None, 1, 9600, &fins(false, 0, 5, 0x04, 0x01));
        assert_eq!(r.summary, "FINS RUN (command) — node 0.5");
    }

    #[test]
    fn unknown_command_reports_its_code() {
        let p = fins(false, 0, 1, 0x7E, 0x7F);
        let r = dissect_fins(None, None, 1, 9600, &p);
        assert_eq!(r.summary, "FINS command 7e7f (command) — node 0.1");
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_fins(None, None, 1, 9600, &[0x80, 0x00, 0x02]);
        assert_eq!(r.summary, "FINS (3 bytes)");
    }
}
