// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Version and type, subtype, reserved, remote index, message counter.
const HEADER: usize = 16;
/// Version 1 is the only one deployed, in the high nibble of the first byte.
const VERSION_1: u8 = 1;

/// Message types (`header.MessageType`).
fn message_name(t: u8) -> Option<&'static str> {
    Some(match t {
        0 => "handshake",
        1 => "message",
        2 => "recv error",
        3 => "lighthouse",
        4 => "test",
        5 => "close tunnel",
        _ => return None,
    })
}

/// Handshake subtypes, which say how far a tunnel has got.
fn handshake_stage(subtype: u8) -> &'static str {
    match subtype {
        0 => "ix psk0",
        1 => "stage 1",
        2 => "stage 2",
        _ => "stage",
    }
}

/// Whether a payload is a Nebula packet.
///
/// Nebula has no magic number, so this checks the version nibble and a known
/// message type. That is weak enough that it is only used for traffic already
/// on Nebula's port.
fn parse(payload: &[u8]) -> Option<(&'static str, u8, u32, u64)> {
    if payload.len() < HEADER {
        return None;
    }
    if payload[0] >> 4 != VERSION_1 {
        return None;
    }
    let name = message_name(payload[0] & 0x0F)?;
    let subtype = payload[1];
    let remote_index = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let counter = u64::from_be_bytes([
        payload[8],
        payload[9],
        payload[10],
        payload[11],
        payload[12],
        payload[13],
        payload[14],
        payload[15],
    ]);
    Some((name, subtype, remote_index, counter))
}

/// Dissect a Nebula packet (UDP 4242).
///
/// Nebula builds a mesh VPN where hosts find each other through lighthouses and
/// then talk directly, rather than routing everything through a hub. The
/// payload is encrypted, but the header says what stage a tunnel is at — and
/// the interesting failure mode is visible there: a pair that keeps exchanging
/// handshakes without ever settling into messages has not managed to reach each
/// other directly.
pub fn dissect_nebula(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match parse(payload) {
        Some(("handshake", subtype, index, _)) => {
            format!(
                "Nebula handshake {} — remote index {index}",
                handshake_stage(subtype)
            )
        }
        Some((name, _, index, counter)) => {
            format!("Nebula {name} — remote index {index}, counter {counter}")
        }
        None => format!("Nebula ({})", super::bytes(payload.len() as u64)),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Nebula,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nebula(msg_type: u8, subtype: u8, index: u32, counter: u64) -> Vec<u8> {
        let mut p = vec![(VERSION_1 << 4) | msg_type, subtype, 0, 0];
        p.extend_from_slice(&index.to_be_bytes());
        p.extend_from_slice(&counter.to_be_bytes());
        p
    }

    #[test]
    fn tunnel_traffic_reports_its_counter() {
        let r = dissect_nebula(None, None, 4242, 4242, &nebula(1, 0, 0xABCD, 99));
        assert_eq!(r.protocol, Protocol::Nebula);
        assert_eq!(r.summary, "Nebula message — remote index 43981, counter 99");
    }

    /// A handshake that never progresses is what a failed direct connection
    /// looks like, so the stage is the useful field there rather than a counter.
    #[test]
    fn handshake_stages_are_named() {
        assert_eq!(
            dissect_nebula(None, None, 1, 4242, &nebula(0, 1, 7, 0)).summary,
            "Nebula handshake stage 1 — remote index 7"
        );
        assert_eq!(
            dissect_nebula(None, None, 1, 4242, &nebula(0, 2, 7, 0)).summary,
            "Nebula handshake stage 2 — remote index 7"
        );
    }

    /// Lighthouse traffic is how hosts find each other; separating it from
    /// tunnel traffic shows whether discovery or transport is the problem.
    #[test]
    fn lighthouse_and_control_messages_are_named() {
        assert!(dissect_nebula(None, None, 1, 4242, &nebula(3, 0, 1, 1))
            .summary
            .starts_with("Nebula lighthouse"));
        assert!(dissect_nebula(None, None, 1, 4242, &nebula(5, 0, 1, 1))
            .summary
            .starts_with("Nebula close tunnel"));
        assert!(dissect_nebula(None, None, 1, 4242, &nebula(2, 0, 1, 1))
            .summary
            .starts_with("Nebula recv error"));
    }

    /// The version and type share a byte; reading the whole byte would fail to
    /// match any type at all.
    #[test]
    fn version_and_type_are_separated() {
        assert!(parse(&nebula(1, 0, 1, 1)).is_some());
        // A foreign version must not be decoded.
        let mut p = nebula(1, 0, 1, 1);
        p[0] = (9 << 4) | 1;
        assert!(parse(&p).is_none());
    }

    #[test]
    fn foreign_payloads_are_not_claimed() {
        assert!(parse(b"GET / HTTP/1.1\r\n\r\n").is_none());
        assert!(parse(&[0u8; 16]).is_none());
        assert!(parse(&[]).is_none());
        // A valid version with a type that does not exist.
        assert!(parse(&nebula(9, 0, 1, 1)).is_none());
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_nebula(None, None, 1, 4242, &[0x11, 0x00]);
        assert_eq!(r.summary, "Nebula (2 bytes)");
    }
}
