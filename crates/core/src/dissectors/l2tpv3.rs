// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// A session id of zero marks the control channel.
const SESSION_CONTROL: u32 = 0;
/// The session id itself, before any cookie.
const SESSION_ID_LEN: usize = 4;
/// A cookie is negotiated as 0, 4 or 8 bytes, so those are the offsets at which
/// the tunnelled frame can begin.
const COOKIE_LENGTHS: [usize; 3] = [0, 4, 8];
/// Where the EtherType sits in the tunnelled Ethernet frame.
const ETHERTYPE_OFFSET: usize = 12;

/// EtherTypes plausible enough to confirm a guess at the cookie length.
fn is_known_ethertype(value: u16) -> bool {
    matches!(value, 0x0800 | 0x86DD | 0x0806 | 0x8100 | 0x88A8)
}

/// Find the tunnelled Ethernet frame, if its position can be established.
///
/// The cookie between the session id and the frame is negotiated when the
/// session is set up and is not described in the packet, so its length cannot
/// be read — only guessed from the three legal values. The guess is accepted
/// only when exactly one of them puts a recognisable EtherType where the frame
/// header says it should be. If two candidates both look plausible the answer
/// is genuinely ambiguous, and reporting the tunnel is better than picking one
/// and being confidently wrong about what it carries.
fn tunnelled_frame(payload: &[u8]) -> Option<&[u8]> {
    let mut found = None;
    for cookie in COOKIE_LENGTHS {
        let at = SESSION_ID_LEN + cookie;
        let Some(frame) = payload.get(at..) else {
            continue;
        };
        let Some(bytes) = frame.get(ETHERTYPE_OFFSET..ETHERTYPE_OFFSET + 2) else {
            continue;
        };
        if is_known_ethertype(u16::from_be_bytes([bytes[0], bytes[1]])) {
            if found.is_some() {
                return None; // ambiguous — two offsets both look right
            }
            found = Some(frame);
        }
    }
    found
}

/// Dissect an L2TPv3 packet carried directly on IP (protocol 115) — the
/// pseudowire version of L2TP, which tunnels whole Ethernet or Frame Relay
/// circuits between sites rather than PPP sessions. A session id of zero marks
/// the control channel (RFC 3931).
pub fn dissect_l2tpv3(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    // A pseudowire carries a whole Ethernet circuit between sites, and that
    // traffic is the point of the tunnel.
    if payload.len() >= SESSION_ID_LEN {
        let session = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        if session != SESSION_CONTROL {
            if let Some(frame) = tunnelled_frame(payload) {
                let mut r = super::dissect(frame);
                r.summary = format!("L2TPv3 session {session} · {}", r.summary);
                return r;
            }
        }
    }

    let summary = if payload.len() >= SESSION_ID_LEN {
        let session = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        if session == SESSION_CONTROL {
            "L2TPv3 control message".to_string()
        } else {
            format!("L2TPv3 session {session} — tunnelled circuit")
        }
    } else {
        "L2TPv3 (truncated)".to_string()
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: None,
        dst_port: None,
        protocol: Protocol::L2tpv3,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_data() {
        let r = dissect_l2tpv3(None, None, &42u32.to_be_bytes());
        assert_eq!(r.protocol, Protocol::L2tpv3);
        assert!(r.summary.contains("session 42"), "{}", r.summary);
    }

    /// A tunnelled Ethernet frame carrying a DNS query, for the tests below.
    fn ethernet_dns() -> Vec<u8> {
        let dns = crate::dissectors::test_helpers::build_dns_query("example.com", 0x1234);
        crate::dissectors::test_helpers::build_udp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            40000,
            53,
            &dns,
        )
    }

    /// With no cookie the frame starts right after the session id, and the
    /// EtherType lands where the frame header says it should.
    #[test]
    fn a_pseudowire_with_no_cookie_is_unwrapped() {
        let mut p = 42u32.to_be_bytes().to_vec();
        p.extend_from_slice(&ethernet_dns());
        let r = dissect_l2tpv3(None, None, &p);
        assert_eq!(r.protocol, Protocol::Dns);
        assert_eq!(r.summary, "L2TPv3 session 42 · DNS Query — example.com");
    }

    /// The cookie length is negotiated and not described in the packet, so it
    /// has to be inferred — an eight-byte cookie shifts the frame accordingly.
    #[test]
    fn an_eight_byte_cookie_is_inferred() {
        let mut p = 7u32.to_be_bytes().to_vec();
        p.extend_from_slice(&[0xAB; 8]); // the cookie
        p.extend_from_slice(&ethernet_dns());
        let r = dissect_l2tpv3(None, None, &p);
        assert_eq!(r.protocol, Protocol::Dns);
        assert!(r.summary.starts_with("L2TPv3 session 7 · "));
    }

    /// When two candidate offsets both look plausible the answer is genuinely
    /// ambiguous, and naming the tunnel beats picking one and being
    /// confidently wrong about its contents.
    #[test]
    fn an_ambiguous_cookie_length_is_not_guessed() {
        // Craft a payload where a known EtherType appears at two of the three
        // candidate positions.
        let mut p = 9u32.to_be_bytes().to_vec();
        p.extend_from_slice(&[0u8; 32]);
        // EtherType IPv4 at the no-cookie offset...
        p[4 + 12..4 + 14].copy_from_slice(&0x0800u16.to_be_bytes());
        // ...and again at the four-byte-cookie offset.
        p[8 + 12..8 + 14].copy_from_slice(&0x0800u16.to_be_bytes());
        assert!(tunnelled_frame(&p).is_none());

        let r = dissect_l2tpv3(None, None, &p);
        assert_eq!(r.summary, "L2TPv3 session 9 — tunnelled circuit");
    }

    /// A payload with no recognisable frame at any offset keeps the plain
    /// tunnel summary rather than being forced into a guess.
    #[test]
    fn a_payload_with_no_recognisable_frame_stays_a_tunnel() {
        let mut p = 3u32.to_be_bytes().to_vec();
        p.extend_from_slice(&[0x5A; 40]);
        assert!(tunnelled_frame(&p).is_none());
        assert_eq!(
            dissect_l2tpv3(None, None, &p).summary,
            "L2TPv3 session 3 — tunnelled circuit"
        );
    }

    #[test]
    fn control_channel() {
        let r = dissect_l2tpv3(None, None, &0u32.to_be_bytes());
        assert_eq!(r.summary, "L2TPv3 control message");
    }
}
