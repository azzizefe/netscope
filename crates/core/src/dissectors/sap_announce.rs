// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! SAP — Session Announcement Protocol (RFC 2974), on UDP 9875.
//!
//! Named `sap_announce` to keep it clearly distinct from SAP the software
//! vendor, which shares the acronym and nothing else.
//!
//! A multicast stream has no directory: a receiver that does not already know
//! the group address and codec cannot join. SAP is the directory. Sources
//! periodically announce themselves to a well-known multicast group, carrying
//! an SDP body that says where the media is and what it is. It is how IPTV
//! set-top boxes and broadcast contribution receivers find their channels.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Version, flags, auth length, message id hash, then the originating source.
const HEADER_V4: usize = 8;
/// Version 1 is the only one defined, in the top three bits.
const VERSION_1: u8 = 0x20;
const VERSION_MASK: u8 = 0xE0;
/// Set when the announcement is withdrawing a session rather than advertising it.
const FLAG_DELETE: u8 = 0x04;
/// Set when the originating source is an IPv6 address, which makes it longer.
const FLAG_IPV6: u8 = 0x10;
/// Set when the payload is encrypted, in which case there is no SDP to read.
const FLAG_ENCRYPTED: u8 = 0x02;

/// Dissect a SAP announcement.
pub fn dissect_sap_announce(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let result = |summary: String| DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SapAnnounce,
        summary,
    };
    if payload.len() < HEADER_V4 {
        return result(format!("SAP ({})", super::bytes(payload.len() as u64)));
    }
    let flags = payload[0];
    if flags & VERSION_MASK != VERSION_1 {
        return result(format!("SAP (unexpected version {})", flags >> 5));
    }
    let deleting = flags & FLAG_DELETE != 0;
    let encrypted = flags & FLAG_ENCRYPTED != 0;

    // The originating source is four bytes, or sixteen when the IPv6 flag is
    // set — getting this wrong would put the payload offset in the wrong place.
    let source_len = if flags & FLAG_IPV6 != 0 { 16 } else { 4 };
    // The authentication header length is counted in 32-bit words.
    let auth_len = payload[1] as usize * 4;
    let body_at = 4 + source_len + auth_len;

    let verb = if deleting { "deletion" } else { "announcement" };
    if encrypted {
        return result(format!("SAP {verb} (encrypted)"));
    }
    match payload.get(body_at..) {
        Some(body) => {
            // The body is normally SDP, optionally preceded by a MIME type.
            let body = strip_payload_type(body);
            match super::sdp::describe(body) {
                Some(inner) => result(format!("SAP {verb} — {inner}")),
                None => result(format!("SAP {verb}")),
            }
        }
        None => result(format!("SAP {verb}")),
    }
}

/// Skip an optional NUL-terminated MIME type before the SDP body.
fn strip_payload_type(body: &[u8]) -> &[u8] {
    // A body that already starts with the SDP version line has no type prefix.
    if body.starts_with(b"v=0") {
        return body;
    }
    match body.iter().position(|&b| b == 0) {
        Some(nul) => body.get(nul + 1..).unwrap_or(body),
        None => body,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissectors::sdp::test_helpers::audio_offer;

    /// Build a SAP packet carrying `body`.
    fn sap(flags: u8, body: &[u8]) -> Vec<u8> {
        let source_len = if flags & FLAG_IPV6 != 0 { 16 } else { 4 };
        let mut p = vec![VERSION_1 | flags, 0x00];
        p.extend_from_slice(&0x1234u16.to_be_bytes()); // message id hash
        p.extend_from_slice(&vec![0x0A; source_len]); // originating source
        p.extend_from_slice(body);
        p
    }

    #[test]
    fn announcement_reports_the_session_it_carries() {
        let r = dissect_sap_announce(None, None, 9875, 9875, &sap(0, &audio_offer("5004")));
        assert_eq!(r.protocol, Protocol::SapAnnounce);
        assert_eq!(
            r.summary,
            "SAP announcement — SDP — audio on 5004 (0 8 96) to 10.0.0.1"
        );
    }

    /// A deletion withdraws a session; reading it as an announcement would show
    /// a channel appearing at the moment it disappears.
    #[test]
    fn deletion_is_distinguished_from_announcement() {
        let r = dissect_sap_announce(None, None, 1, 9875, &sap(FLAG_DELETE, &audio_offer("5004")));
        assert!(r.summary.starts_with("SAP deletion —"));
    }

    /// The IPv6 flag changes the header length; ignoring it would put the body
    /// offset twelve bytes short and turn the SDP into gibberish.
    #[test]
    fn ipv6_source_shifts_the_body_offset() {
        let r = dissect_sap_announce(None, None, 1, 9875, &sap(FLAG_IPV6, &audio_offer("5004")));
        assert!(r.summary.contains("audio on 5004"));
    }

    /// An optional MIME type may precede the SDP.
    #[test]
    fn payload_type_prefix_is_skipped() {
        let mut body = b"application/sdp\0".to_vec();
        body.extend_from_slice(&audio_offer("5004"));
        let r = dissect_sap_announce(None, None, 1, 9875, &sap(0, &body));
        assert!(r.summary.contains("audio on 5004"));
    }

    #[test]
    fn encrypted_announcements_say_so() {
        let r = dissect_sap_announce(None, None, 1, 9875, &sap(FLAG_ENCRYPTED, b"\xff\xff"));
        assert_eq!(r.summary, "SAP announcement (encrypted)");
    }

    #[test]
    fn foreign_version_is_not_decoded() {
        let mut p = sap(0, &audio_offer("5004"));
        p[0] = 0x40;
        assert_eq!(
            dissect_sap_announce(None, None, 1, 9875, &p).summary,
            "SAP (unexpected version 2)"
        );
    }

    #[test]
    fn body_that_is_not_sdp_still_names_the_action() {
        let r = dissect_sap_announce(None, None, 1, 9875, &sap(0, b"not sdp at all"));
        assert_eq!(r.summary, "SAP announcement");
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_sap_announce(None, None, 1, 9875, &[0x20, 0x00]);
        assert_eq!(r.summary, "SAP (2 bytes)");
    }
}
