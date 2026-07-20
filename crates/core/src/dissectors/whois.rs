// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a WHOIS message (TCP 43). The client sends a single line — the
/// domain or object being looked up — and the server replies with free text
/// (RFC 3912).
pub fn dissect_whois(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let line = super::first_text_line(payload);
    let summary = if line.is_empty() {
        format!("WHOIS ({})", super::bytes(payload.len() as u64))
    } else {
        format!("WHOIS — {}", super::truncate(&line, 60))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Whois,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_line() {
        let r = dissect_whois(None, None, 40000, 43, b"example.com\r\n");
        assert_eq!(r.protocol, Protocol::Whois);
        assert_eq!(r.summary, "WHOIS — example.com");
    }
}
