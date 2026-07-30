// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Syslog severity names, indexed by the low 3 bits of the PRI value (RFC 5424).
const SEVERITIES: [&str; 8] = [
    "Emergency",
    "Alert",
    "Critical",
    "Error",
    "Warning",
    "Notice",
    "Info",
    "Debug",
];

/// Whether a payload is a syslog message.
///
/// Used to settle TCP 514, where the IANA assignment is `shell` (rsh) but
/// syslog-over-TCP squats in practice — the two are trivially distinguishable
/// because syslog always opens with its priority marker and rsh does not.
///
/// RFC 6587 also allows a decimal length before the message, so a leading run
/// of digits is stepped over before looking for the marker.
pub(crate) fn looks_like_syslog(payload: &[u8]) -> bool {
    let after_length = payload
        .iter()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(payload.len());
    let rest = match payload.get(after_length) {
        // Octet-counted framing: digits, a space, then the message.
        Some(b' ') if after_length > 0 => &payload[after_length + 1..],
        _ => payload,
    };
    // A priority marker is `<` then one to three digits then `>`.
    if rest.first() != Some(&b'<') {
        return false;
    }
    let digits = rest[1..].iter().take_while(|b| b.is_ascii_digit()).count();
    (1..=3).contains(&digits) && rest.get(1 + digits) == Some(&b'>')
}

/// Dissect a Syslog message (UDP 514, and TCP where it is configured). Every
/// syslog line begins with a `<PRI>` value that packs the facility (PRI / 8)
/// and severity (PRI % 8); the remainder is the free-form log text
/// (RFC 3164 / RFC 5424).
pub fn dissect_syslog(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = parse(payload)
        .unwrap_or_else(|| format!("Syslog message ({})", super::bytes(payload.len() as u64)));
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Syslog,
        summary,
    }
}

fn parse(payload: &[u8]) -> Option<String> {
    if payload.first() != Some(&b'<') {
        return None;
    }
    let close = payload.iter().position(|&b| b == b'>')?;
    // PRI is 1–3 digits, so '>' sits at index 2..=4.
    if !(2..=4).contains(&close) {
        return None;
    }
    let pri: u16 = std::str::from_utf8(&payload[1..close]).ok()?.parse().ok()?;
    let facility = pri / 8;
    let sev = *SEVERITIES.get((pri % 8) as usize)?;
    let msg = super::truncate(&super::first_text_line(&payload[close + 1..]), 60);
    if msg.is_empty() {
        Some(format!("Syslog {sev} (facility {facility})"))
    } else {
        Some(format!("Syslog {sev} (facility {facility}) — {msg}"))
    }
}

#[cfg(test)]
mod tests {

    /// TCP 514 is assigned to rsh but syslog squats there, so recognition has
    /// to be reliable in both directions or one protocol eats the other.
    #[test]
    fn syslog_is_told_apart_from_rsh_on_the_shared_port() {
        assert!(looks_like_syslog(b"<134>Oct 11 22:14:15 host app: started"));
        assert!(looks_like_syslog(
            b"<13>1 2026-07-19T10:00:00Z host - - - - hi"
        ));
        // An rsh conversation opens with NUL-separated user names, not a marker.
        assert!(!looks_like_syslog(b"\0root\0root\0ls -l\0"));
        assert!(!looks_like_syslog(b"GET / HTTP/1.1\r\n"));
        assert!(!looks_like_syslog(b""));
    }

    /// RFC 6587 allows a decimal length in front of the message, which has to
    /// be stepped over before the marker can be found.
    #[test]
    fn octet_counted_framing_is_recognised() {
        assert!(looks_like_syslog(
            b"38 <134>Oct 11 22:14:15 host app: started"
        ));
        // A bare number with no marker after it is not syslog.
        assert!(!looks_like_syslog(b"38 hello world"));
    }

    /// A priority marker is one to three digits; anything else is something
    /// that merely starts with an angle bracket.
    #[test]
    fn a_malformed_marker_is_rejected() {
        assert!(!looks_like_syslog(b"<>hello"));
        assert!(!looks_like_syslog(b"<9999>hello"));
        assert!(!looks_like_syslog(b"<abc>hello"));
        assert!(!looks_like_syslog(b"<134 hello"));
        assert!(looks_like_syslog(b"<0>x"));
        assert!(looks_like_syslog(b"<191>x"));
    }
    use super::*;

    #[test]
    fn parses_pri_severity_and_facility() {
        // <34> = facility 4 (auth), severity 2 (Critical).
        let r = dissect_syslog(
            None,
            None,
            40000,
            514,
            b"<34>Oct 11 22:14:15 host su: failed",
        );
        assert_eq!(r.protocol, Protocol::Syslog);
        assert!(
            r.summary.starts_with("Syslog Critical (facility 4)"),
            "{}",
            r.summary
        );
        assert!(r.summary.contains("failed"));
    }

    #[test]
    fn non_syslog_payload_falls_back() {
        let r = dissect_syslog(None, None, 40000, 514, b"not a syslog line");
        assert_eq!(r.protocol, Protocol::Syslog);
        assert!(r.summary.contains("Syslog message"));
    }
}
