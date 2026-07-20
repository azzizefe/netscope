// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a BGP message (TCP 179).
///
/// BGP is the protocol that glues the internet's networks together — it's how
/// autonomous systems tell each other which IP prefixes they can reach. Each
/// message starts with a 19-byte header: a 16-byte marker (all ones), a 2-byte
/// length, and a type. OPEN sets up a session, UPDATE advertises or withdraws
/// routes, KEEPALIVE holds it open, NOTIFICATION tears it down on error. We name
/// the message and, for OPEN, surface the advertised AS number.
pub fn dissect_bgp(
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
        protocol: Protocol::Bgp,
        summary,
    };

    if payload.len() < 19 {
        return result("BGP (partial)".into());
    }

    let msg_type = payload[18];
    let summary = match msg_type {
        1 => {
            // OPEN: version(1), my-AS(2), hold-time(2), BGP-id(4)...
            let my_as = u16::from_be_bytes([payload[20], payload[21]]);
            format!("BGP OPEN — AS {my_as}")
        }
        2 => "BGP UPDATE".to_string(),
        3 => {
            // A notification is a session being torn down, and the code says
            // by whom and why. "error 6/2" is an operator shutting the peer
            // down deliberately; "error 4" is the peer going silent; "error
            // 6/1" is it sending more routes than the limit allows, which is
            // what a route leak looks like from the receiving side. All three
            // read identically as numbers.
            let (code, subcode) = (payload.get(19).copied(), payload.get(20).copied());
            match (code, subcode) {
                (Some(c), Some(s)) => format!("BGP NOTIFICATION — {}", notification_text(c, s)),
                _ => "BGP NOTIFICATION".to_string(),
            }
        }
        4 => "BGP KEEPALIVE".to_string(),
        5 => "BGP ROUTE-REFRESH".to_string(),
        other => format!("BGP message type {other}"),
    };
    result(summary)
}

/// Why a session was torn down, from the notification's code and subcode.
///
/// The subcode is only meaningful within its code, so the two are looked up
/// together rather than separately.
fn notification_name(code: u8, subcode: u8) -> Option<&'static str> {
    Some(match (code, subcode) {
        (1, 1) => "connection not synchronised",
        (1, 2) => "bad message length",
        (1, 3) => "bad message type",
        (1, _) => "message header error",

        (2, 1) => "unsupported BGP version",
        (2, 2) => "the peer's AS number is not the one expected",
        (2, 3) => "bad BGP identifier",
        (2, 4) => "unsupported optional parameter",
        (2, 6) => "unacceptable hold time",
        (2, 7) => "unsupported capability",
        (2, _) => "OPEN message error",

        (3, 1) => "malformed attribute list",
        (3, 2) => "unrecognised well-known attribute",
        (3, 3) => "missing well-known attribute",
        (3, 4) => "attribute flags error",
        (3, 5) => "attribute length error",
        (3, 6) => "invalid ORIGIN attribute",
        (3, 8) => "invalid NEXT_HOP attribute",
        (3, 9) => "optional attribute error",
        (3, 10) => "invalid network field",
        (3, 11) => "malformed AS_PATH",
        (3, _) => "UPDATE message error",

        // The hold timer has no subcodes: the peer simply stopped answering.
        (4, _) => "hold timer expired (the peer went silent)",
        (5, _) => "state machine error",

        (6, 1) => "too many prefixes received (the configured limit was hit)",
        (6, 2) => "administrative shutdown",
        (6, 3) => "the peer was de-configured",
        (6, 4) => "administrative reset",
        (6, 5) => "connection rejected",
        (6, 6) => "a configuration change",
        (6, 7) => "connection collision resolution",
        (6, 8) => "the router is out of resources",
        (6, _) => "cease",

        (7, _) => "ROUTE-REFRESH message error",
        _ => return None,
    })
}

fn notification_text(code: u8, subcode: u8) -> String {
    match notification_name(code, subcode) {
        Some(text) => format!("{text} (error {code}/{subcode})"),
        None => format!("error {code}/{subcode}"),
    }
}

/// Whether a TCP payload looks like BGP: the 16-byte all-ones marker and a
/// sane length/type. Lets BGP be recognised even off port 179.
pub fn looks_like_bgp(payload: &[u8]) -> bool {
    payload.len() >= 19
        && payload[..16].iter().all(|&b| b == 0xff)
        && (1..=5).contains(&payload[18])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(msg_type: u8, extra: &[u8]) -> Vec<u8> {
        let mut p = vec![0xff; 16];
        let len = (19 + extra.len()) as u16;
        p.extend_from_slice(&len.to_be_bytes());
        p.push(msg_type);
        p.extend_from_slice(extra);
        p
    }

    #[test]
    fn keepalive() {
        let r = dissect_bgp(None, None, 50000, 179, &header(4, &[]));
        assert_eq!(r.protocol, Protocol::Bgp);
        assert_eq!(r.summary, "BGP KEEPALIVE");
    }

    #[test]
    fn open_shows_as() {
        // version, my-AS = 65001, ...
        let mut extra = vec![4];
        extra.extend_from_slice(&65001u16.to_be_bytes());
        extra.extend_from_slice(&[0, 180, 1, 2, 3, 4, 0]);
        let r = dissect_bgp(None, None, 179, 50000, &header(1, &extra));
        assert_eq!(r.summary, "BGP OPEN — AS 65001");
    }

    #[test]
    fn detection() {
        assert!(looks_like_bgp(&header(2, &[])));
        assert!(!looks_like_bgp(&[0u8; 19]));
    }

    /// A notification is a session ending. The three commonest causes read
    /// identically as numbers and mean entirely different things.
    #[test]
    fn a_notification_says_why_the_session_ended() {
        let r = dissect_bgp(None, None, 179, 50000, &header(3, &[6, 2]));
        assert_eq!(
            r.summary,
            "BGP NOTIFICATION — administrative shutdown (error 6/2)"
        );
        assert!(dissect_bgp(None, None, 179, 1, &header(3, &[4, 0]))
            .summary
            .contains("the peer went silent"));
        assert!(dissect_bgp(None, None, 179, 1, &header(3, &[6, 1]))
            .summary
            .contains("too many prefixes"));
    }

    /// A mismatched AS number is a configuration error on one side, and it
    /// happens whenever a peering is first set up wrongly.
    #[test]
    fn a_misconfigured_peering_is_named() {
        assert!(dissect_bgp(None, None, 179, 1, &header(3, &[2, 2]))
            .summary
            .contains("not the one expected"));
        assert!(dissect_bgp(None, None, 179, 1, &header(3, &[2, 6]))
            .summary
            .contains("unacceptable hold time"));
    }

    /// The subcode only means something inside its code — subcode 2 is a bad
    /// message length under code 1 and an administrative shutdown under code 6.
    /// Looking them up separately would conflate the two.
    #[test]
    fn the_subcode_is_read_in_the_context_of_its_code() {
        let header_error = dissect_bgp(None, None, 179, 1, &header(3, &[1, 2])).summary;
        let cease = dissect_bgp(None, None, 179, 1, &header(3, &[6, 2])).summary;
        assert!(
            header_error.contains("bad message length"),
            "{header_error}"
        );
        assert!(cease.contains("administrative shutdown"), "{cease}");
    }

    /// An unrecognised code keeps its numbers rather than being given the
    /// meaning of whichever entry was nearest.
    #[test]
    fn an_unknown_notification_keeps_its_numbers() {
        assert_eq!(
            dissect_bgp(None, None, 179, 1, &header(3, &[99, 1])).summary,
            "BGP NOTIFICATION — error 99/1"
        );
    }

    /// A code with an unlisted subcode still names the category.
    #[test]
    fn an_unlisted_subcode_still_names_its_category() {
        assert!(dissect_bgp(None, None, 179, 1, &header(3, &[6, 200]))
            .summary
            .contains("cease"));
        assert!(dissect_bgp(None, None, 179, 1, &header(3, &[3, 200]))
            .summary
            .contains("UPDATE message error"));
    }

    /// A notification with no body must not panic.
    #[test]
    fn a_bodyless_notification_does_not_panic() {
        let r = dissect_bgp(None, None, 179, 1, &header(3, &[]));
        assert_eq!(r.summary, "BGP NOTIFICATION");
    }
}
