// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The greeting every Fox connection opens with.
const GREETING: &[u8] = b"fox a 1 -1 fox hello";

/// Whether a payload is a Niagara Fox message. The protocol has no length
/// prefix or magic number — it opens with a fixed text greeting, so that is
/// what identifies it.
pub(crate) fn looks_like_fox(payload: &[u8]) -> bool {
    payload.starts_with(GREETING)
}

/// Pull a value out of the greeting's `key=value;` body.
///
/// Values carry a one-letter type tag — `s:` for a string, `i:` for an integer
/// — which is an encoding detail, not something to show the reader, so it is
/// stripped.
fn field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("{key}=");
    let start = text.find(&needle)? + needle.len();
    let rest = &text[start..];
    let end = rest.find(';').unwrap_or(rest.len());
    let value = rest[..end].trim();
    let value = match value.split_once(':') {
        // Only a single-letter tag is a type prefix; a colon inside the value
        // itself (a path, a timestamp) must survive.
        Some((tag, body)) if tag.len() == 1 && tag.chars().all(|c| c.is_ascii_alphabetic()) => body,
        _ => value,
    };
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// Dissect a Niagara Fox message — the protocol Tridium's building-automation
/// controllers use, on TCP 1911 (and 4911 for the TLS form).
///
/// The opening greeting is unauthenticated and remarkably candid: it announces
/// the station name, the product version and the host operating system before
/// any credentials are exchanged. That makes it a favourite for inventorying
/// building-management systems, and it is the part worth surfacing.
pub fn dissect_fox(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let text = String::from_utf8_lossy(&payload[..payload.len().min(2048)]);
    let summary = if looks_like_fox(payload) {
        let host = field(&text, "hostName");
        let version = field(&text, "brandId").or_else(|| field(&text, "vmVersion"));
        let os = field(&text, "os");
        let mut parts = Vec::new();
        if let Some(h) = host {
            parts.push(super::truncate(h, 32));
        }
        if let Some(v) = version {
            parts.push(super::truncate(v, 24));
        }
        if let Some(o) = os {
            parts.push(super::truncate(o, 24));
        }
        if parts.is_empty() {
            "Fox hello".to_string()
        } else {
            format!("Fox hello — {}", parts.join(" · "))
        }
    } else {
        // After the greeting the session is a stream of framed messages we do
        // not decode; report the size rather than guessing at the contents.
        format!("Fox ({})", super::bytes(payload.len() as u64))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Fox,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(body: &str) -> Vec<u8> {
        format!("fox a 1 -1 fox hello\n{{\n{body}}};;\n").into_bytes()
    }

    #[test]
    fn greeting_reports_station_version_and_os() {
        let p = hello(
            "fox.version=s:1.0.1;\nhostName=s:BMS-TOWER-3;\n\
             brandId=s:Tridium;\nvmVersion=s:1.8.0_121;\nos=s:QNX (x86);\n",
        );
        let r = dissect_fox(None, None, 40000, 1911, &p);
        assert_eq!(r.protocol, Protocol::Fox);
        assert_eq!(r.summary, "Fox hello — BMS-TOWER-3 · Tridium · QNX (x86)");
    }

    #[test]
    fn greeting_without_fields_is_still_recognised() {
        let r = dissect_fox(None, None, 40000, 1911, b"fox a 1 -1 fox hello\n{}\n");
        assert_eq!(r.summary, "Fox hello");
    }

    /// Missing fields must not shift the others — a station that reports only
    /// its name should say so, not borrow a neighbouring value.
    #[test]
    fn partial_fields_are_reported_independently() {
        let p = hello("hostName=s:METER-01;\n");
        let r = dissect_fox(None, None, 1, 1911, &p);
        assert_eq!(r.summary, "Fox hello — METER-01");
    }

    /// A colon inside the value itself must survive; only the leading
    /// single-letter type tag is an encoding artefact.
    #[test]
    fn only_the_type_tag_is_stripped() {
        let p = hello(
            "hostName=s:host:with:colons;
",
        );
        let r = dissect_fox(None, None, 1, 1911, &p);
        assert_eq!(r.summary, "Fox hello — host:with:colons");
    }

    #[test]
    fn post_greeting_traffic_is_reported_by_size() {
        let r = dissect_fox(None, None, 1, 1911, &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(r.summary, "Fox (4 bytes)");
    }

    /// The greeting is the only reliable identifier, so it must not match
    /// arbitrary text arriving on the same port.
    #[test]
    fn foreign_text_is_not_a_greeting() {
        assert!(!looks_like_fox(b"GET / HTTP/1.1"));
        assert!(!looks_like_fox(b"fox"));
        assert!(!looks_like_fox(b""));
        assert!(looks_like_fox(b"fox a 1 -1 fox hello\n{}"));
    }

    #[test]
    fn long_values_are_truncated() {
        let long = "x".repeat(100);
        let p = hello(&format!("hostName=s:{long};\n"));
        let r = dissect_fox(None, None, 1, 1911, &p);
        assert!(
            r.summary.len() < 80,
            "summary should be capped: {}",
            r.summary
        );
        assert!(r.summary.contains('…'));
    }

    #[test]
    fn invalid_utf8_does_not_panic() {
        let mut p = b"fox a 1 -1 fox hello\n{hostName=s:".to_vec();
        p.extend_from_slice(&[0xFF, 0xFE, 0xFD]);
        p.extend_from_slice(b";}\n");
        let _ = dissect_fox(None, None, 1, 1911, &p);
    }
}
