// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// PCEP message types (RFC 5440 §6.1, extended by RFC 8231 for stateful PCE
/// and RFC 8281 for PCE-initiated paths).
fn message_name(t: u8) -> Option<&'static str> {
    Some(match t {
        1 => "Open",
        2 => "Keepalive",
        3 => "Path Computation Request",
        4 => "Path Computation Reply",
        5 => "Notification",
        6 => "Error",
        7 => "Close",
        8 => "Path Computation Monitoring Request",
        9 => "Path Computation Monitoring Reply",
        10 => "Report",
        11 => "Update",
        12 => "Initiate",
        13 => "StartTLS",
        _ => return None,
    })
}

/// The common header (RFC 5440 §6.1): a version and flags byte, the message
/// type, then a length that covers the header too.
const HEADER: usize = 4;
/// Version 1 is the only one defined, and sits in the top three bits.
const VERSION_1: u8 = 0x20;
const VERSION_MASK: u8 = 0xE0;

/// Dissect a PCEP message — how a router asks a central controller to compute a
/// path across the network, on TCP 4189 (RFC 5440).
///
/// PCEP is the signalling behind traffic engineering: rather than every router
/// working out its own paths, a path computation element with a full view of
/// the topology decides, and hands the answer back. The stateful extensions let
/// the controller update or create paths on its own initiative, which is what
/// makes a segment-routing network centrally steerable.
pub fn dissect_pcep(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary =
        parse(payload).unwrap_or_else(|| format!("PCEP ({})", super::bytes(payload.len() as u64)));
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Pcep,
        summary,
    }
}

fn parse(payload: &[u8]) -> Option<String> {
    let flags = *payload.first()?;
    if flags & VERSION_MASK != VERSION_1 {
        return None;
    }
    let msg_type = *payload.get(1)?;
    let length = u16::from_be_bytes([*payload.get(2)?, *payload.get(3)?]) as usize;
    // The length covers the header, so anything smaller is malformed.
    if length < HEADER {
        return None;
    }
    Some(match message_name(msg_type) {
        Some(name) => format!("PCEP {name}"),
        None => format!("PCEP message type {msg_type}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a PCEP message of the given type.
    fn pcep(msg_type: u8, length: u16) -> Vec<u8> {
        let mut p = vec![VERSION_1, msg_type];
        p.extend_from_slice(&length.to_be_bytes());
        p
    }

    #[test]
    fn session_setup_is_named() {
        let r = dissect_pcep(None, None, 40000, 4189, &pcep(1, 12));
        assert_eq!(r.protocol, Protocol::Pcep);
        assert_eq!(r.summary, "PCEP Open");
        let r = dissect_pcep(None, None, 40000, 4189, &pcep(2, 4));
        assert_eq!(r.summary, "PCEP Keepalive");
    }

    #[test]
    fn path_computation_request_and_reply() {
        let r = dissect_pcep(None, None, 1, 4189, &pcep(3, 40));
        assert_eq!(r.summary, "PCEP Path Computation Request");
        let r = dissect_pcep(None, None, 1, 4189, &pcep(4, 60));
        assert_eq!(r.summary, "PCEP Path Computation Reply");
    }

    /// The stateful extensions are what let a controller drive paths rather
    /// than only answer questions about them.
    #[test]
    fn stateful_messages_are_named() {
        assert_eq!(
            dissect_pcep(None, None, 1, 4189, &pcep(10, 40)).summary,
            "PCEP Report"
        );
        assert_eq!(
            dissect_pcep(None, None, 1, 4189, &pcep(11, 40)).summary,
            "PCEP Update"
        );
        assert_eq!(
            dissect_pcep(None, None, 1, 4189, &pcep(12, 40)).summary,
            "PCEP Initiate"
        );
    }

    /// The version occupies the top three bits; reading the whole byte would
    /// reject every message that sets a flag.
    #[test]
    fn flags_alongside_the_version_are_tolerated() {
        let mut p = pcep(1, 12);
        p[0] = VERSION_1 | 0x03; // version 1 with flag bits set
        assert_eq!(dissect_pcep(None, None, 1, 4189, &p).summary, "PCEP Open");
    }

    /// A foreign version means this is not PCEP and must not be claimed.
    #[test]
    fn foreign_version_is_not_claimed() {
        let mut p = pcep(1, 12);
        p[0] = 0x40; // version 2
        assert_eq!(
            dissect_pcep(None, None, 1, 4189, &p).summary,
            "PCEP (4 bytes)"
        );
    }

    /// The length includes the header, so a smaller value is malformed.
    #[test]
    fn length_shorter_than_the_header_is_rejected() {
        let r = dissect_pcep(None, None, 1, 4189, &pcep(1, 2));
        assert_eq!(r.summary, "PCEP (4 bytes)");
    }

    #[test]
    fn unknown_type_reports_its_number() {
        let r = dissect_pcep(None, None, 1, 4189, &pcep(99, 8));
        assert_eq!(r.summary, "PCEP message type 99");
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_pcep(None, None, 1, 4189, &[VERSION_1, 1]);
        assert_eq!(r.summary, "PCEP (2 bytes)");
    }
}
