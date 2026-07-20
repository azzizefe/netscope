// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// TWAMP-Control command numbers (RFC 5357 §3.5, extending RFC 4656).
fn command_name(cmd: u8) -> Option<&'static str> {
    Some(match cmd {
        1 => "Forbidden",
        2 => "Start-Sessions",
        3 => "Stop-Sessions",
        4 => "Reserved",
        5 => "Request-TW-Session",
        6 => "Experimentation",
        _ => return None,
    })
}

/// Accept codes returned by the server (RFC 4656 §3.3).
fn accept_name(code: u8) -> &'static str {
    match code {
        0 => "accepted",
        1 => "rejected",
        2 => "internal error",
        3 => "unsupported feature",
        4 => "permanent resource limitation",
        5 => "temporary resource limitation",
        _ => "unknown status",
    }
}

/// The server greeting is a fixed 64 bytes: twelve unused, the modes bitmask,
/// a challenge, a salt and an iteration count.
const GREETING_LEN: usize = 64;
/// The first twelve bytes of the greeting are reserved and must be zero, which
/// is what identifies it.
const GREETING_PADDING: usize = 12;

/// Dissect a TWAMP-Control message — the negotiation that sets up a two-way
/// delay measurement, on TCP 862 (RFC 5357).
///
/// TWAMP is how an operator proves a link meets its latency and loss
/// commitments. The control channel arranges the test: which ports the probes
/// will use and when to start. The probes themselves then run over UDP on
/// negotiated ports, which is why the control exchange is the part that can be
/// found reliably.
pub fn dissect_twamp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary =
        parse(payload).unwrap_or_else(|| format!("TWAMP ({})", super::bytes(payload.len() as u64)));
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Twamp,
        summary,
    }
}

fn parse(payload: &[u8]) -> Option<String> {
    // The greeting opens the connection and is recognisable by its reserved
    // padding followed by a modes bitmask.
    if payload.len() >= GREETING_LEN && payload[..GREETING_PADDING].iter().all(|&b| b == 0) {
        let modes = u32::from_be_bytes([
            payload[GREETING_PADDING],
            payload[GREETING_PADDING + 1],
            payload[GREETING_PADDING + 2],
            payload[GREETING_PADDING + 3],
        ]);
        return Some(if modes == 0 {
            "TWAMP server greeting — no modes offered".to_string()
        } else {
            format!("TWAMP server greeting — modes 0x{modes:08x}")
        });
    }

    // Otherwise the first byte is a command.
    let command = *payload.first()?;
    let name = command_name(command)?;
    // A Start-Sessions or Stop-Sessions reply carries an accept code.
    if matches!(command, 2 | 3) {
        if let Some(&code) = payload.get(1) {
            return Some(format!("TWAMP {name} — {}", accept_name(code)));
        }
    }
    Some(format!("TWAMP {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn greeting(modes: u32) -> Vec<u8> {
        let mut p = vec![0u8; GREETING_PADDING];
        p.extend_from_slice(&modes.to_be_bytes());
        p.resize(GREETING_LEN, 0);
        p
    }

    #[test]
    fn server_greeting_reports_the_modes_offered() {
        let r = dissect_twamp(None, None, 862, 40000, &greeting(0x0000_0001));
        assert_eq!(r.protocol, Protocol::Twamp);
        assert_eq!(r.summary, "TWAMP server greeting — modes 0x00000001");
    }

    /// A greeting offering no modes is how a server refuses a client outright,
    /// which is worth reading differently from one that offers something.
    #[test]
    fn a_greeting_with_no_modes_is_a_refusal() {
        let r = dissect_twamp(None, None, 862, 40000, &greeting(0));
        assert_eq!(r.summary, "TWAMP server greeting — no modes offered");
    }

    #[test]
    fn session_setup_commands_are_named() {
        let r = dissect_twamp(None, None, 40000, 862, &[5, 0, 0, 0]);
        assert_eq!(r.summary, "TWAMP Request-TW-Session");
    }

    /// Whether a measurement session was actually accepted is the fact that
    /// decides if any probes will follow.
    #[test]
    fn accept_codes_are_named() {
        assert_eq!(
            dissect_twamp(None, None, 862, 1, &[2, 0, 0, 0]).summary,
            "TWAMP Start-Sessions — accepted"
        );
        assert_eq!(
            dissect_twamp(None, None, 862, 1, &[2, 1, 0, 0]).summary,
            "TWAMP Start-Sessions — rejected"
        );
        assert_eq!(
            dissect_twamp(None, None, 862, 1, &[3, 5, 0, 0]).summary,
            "TWAMP Stop-Sessions — temporary resource limitation"
        );
    }

    /// The greeting's leading padding is what tells it apart from a command;
    /// a message that merely starts with a zero byte is not one.
    #[test]
    fn a_short_zero_message_is_not_mistaken_for_a_greeting() {
        let r = dissect_twamp(None, None, 1, 862, &[0u8; 16]);
        assert_eq!(r.summary, "TWAMP (16 bytes)");
    }

    #[test]
    fn unknown_command_is_not_claimed() {
        let r = dissect_twamp(None, None, 1, 862, &[99, 0, 0, 0]);
        assert_eq!(r.summary, "TWAMP (4 bytes)");
    }

    #[test]
    fn empty_input_does_not_panic() {
        let r = dissect_twamp(None, None, 1, 862, &[]);
        assert_eq!(r.summary, "TWAMP (0 bytes)");
    }
}
