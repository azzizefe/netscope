// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The blank line that separates SIP headers from the body. Written as byte
/// values rather than an escaped literal so there is no ambiguity about what
/// is actually being matched.
const HEADER_END_CRLF: [u8; 4] = [13, 10, 13, 10];
const HEADER_END_LF: [u8; 2] = [10, 10];

/// The body of a SIP message, which follows the blank line after the headers.
fn sdp_body(payload: &[u8]) -> Option<&[u8]> {
    // Both line endings appear in practice, so look for either separator and
    // take whichever comes first.
    let crlf = payload
        .windows(4)
        .position(|w| w == HEADER_END_CRLF)
        .map(|i| i + 4);
    let lf = payload
        .windows(2)
        .position(|w| w == HEADER_END_LF)
        .map(|i| i + 2);
    let start = match (crlf, lf) {
        (Some(a), Some(b)) => a.min(b),
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) => return None,
    };
    payload.get(start..)
}

const SIP_METHODS: &[&str] = &[
    "INVITE",
    "ACK",
    "BYE",
    "CANCEL",
    "REGISTER",
    "OPTIONS",
    "INFO",
    "PRACK",
    "SUBSCRIBE",
    "NOTIFY",
    "PUBLISH",
    "MESSAGE",
    "REFER",
    "UPDATE",
];

/// Dissect a SIP message (UDP/TCP 5060/5061). SIP is a text protocol like HTTP;
/// the first line is either a request (`INVITE sip:bob@host SIP/2.0`) or a
/// status response (`SIP/2.0 200 OK`).
pub fn dissect_sip(
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
        protocol: Protocol::Sip,
        summary,
    };

    let first_line = payload
        .split(|&b| b == b'\r' || b == b'\n')
        .next()
        .map(|l| String::from_utf8_lossy(l).trim().to_string())
        .unwrap_or_default();

    let summary = parse_sip_line(&first_line).unwrap_or_else(|| "SIP message".into());

    // An invite or a response often carries an SDP body saying where the media
    // will flow. That is the fact a reader actually wants, because the RTP
    // itself lands on a port chosen at call time.
    match sdp_body(payload).and_then(super::sdp::describe) {
        Some(sdp) => result(format!("{summary} — {}", sdp.trim_start_matches("SDP — "))),
        None => result(summary),
    }
}

fn parse_sip_line(line: &str) -> Option<String> {
    if line.is_empty() {
        return None;
    }

    // Status response: "SIP/2.0 200 OK"
    if let Some(rest) = line.strip_prefix("SIP/2.0 ") {
        return Some(format!("SIP {}", rest.trim()));
    }

    // Request: "METHOD Request-URI SIP/2.0"
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    if SIP_METHODS.contains(&method) {
        let uri = parts.next().unwrap_or("");
        if uri.is_empty() {
            return Some(format!("SIP {method}"));
        }
        return Some(format!("SIP {method} — {uri}"));
    }

    None
}

#[cfg(test)]
mod tests {

    /// An invite carrying SDP should say where the media will go — that is the
    /// fact a reader wants, because the RTP itself lands on a port chosen at
    /// call time and is otherwise unfindable.
    #[test]
    fn invite_folds_in_its_sdp_body() {
        let mut p =
            b"INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1\r\n\r\n".to_vec();
        p.extend_from_slice(&crate::dissectors::sdp::test_helpers::audio_offer("49170"));
        let r = dissect_sip(None, None, 5060, 5060, &p);
        assert_eq!(r.protocol, Protocol::Sip);
        assert!(
            r.summary.contains("audio on 49170"),
            "expected the media details, got {}",
            r.summary
        );
    }

    /// A message with no body keeps its plain summary rather than gaining an
    /// empty suffix.
    #[test]
    fn message_without_a_body_is_unchanged() {
        let p = b"SIP/2.0 100 Trying\r\nVia: SIP/2.0/UDP 10.0.0.1\r\n\r\n";
        let r = dissect_sip(None, None, 5060, 5060, p);
        assert!(
            !r.summary.contains('\u{2014}'),
            "unexpected suffix: {}",
            r.summary
        );
    }
    use super::*;

    #[test]
    fn invite_request_parsed() {
        let msg = b"INVITE sip:bob@biloxi.com SIP/2.0\r\nVia: SIP/2.0/UDP\r\n\r\n";
        let r = dissect_sip(None, None, 5060, 5060, msg);
        assert_eq!(r.protocol, Protocol::Sip);
        assert_eq!(r.summary, "SIP INVITE — sip:bob@biloxi.com");
    }

    #[test]
    fn status_response_parsed() {
        let msg = b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP\r\n\r\n";
        let r = dissect_sip(None, None, 5060, 5060, msg);
        assert_eq!(r.summary, "SIP 200 OK");
    }

    #[test]
    fn register_request_parsed() {
        let msg = b"REGISTER sip:registrar.example.com SIP/2.0\r\n";
        let r = dissect_sip(None, None, 5060, 5060, msg);
        assert_eq!(r.summary, "SIP REGISTER — sip:registrar.example.com");
    }

    #[test]
    fn non_sip_falls_back() {
        let r = dissect_sip(None, None, 5060, 5060, b"garbage data here");
        assert_eq!(r.protocol, Protocol::Sip);
        assert_eq!(r.summary, "SIP message");
    }
}
