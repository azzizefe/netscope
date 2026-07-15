// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

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
    result(summary)
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
