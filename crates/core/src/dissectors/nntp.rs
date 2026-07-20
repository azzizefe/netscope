// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an NNTP message (TCP 119) — Usenet news transfer. Commands are
/// text words (ARTICLE, GROUP, POST…); responses start with a 3-digit status
/// code (RFC 3977).
pub fn dissect_nntp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let line = super::first_text_line(payload);
    let summary = if line.is_empty() {
        format!("NNTP ({})", super::bytes(payload.len() as u64))
    } else if line.len() >= 3 && line.as_bytes()[..3].iter().all(u8::is_ascii_digit) {
        format!("NNTP Response — {}", super::truncate(&line, 55))
    } else {
        format!("NNTP — {}", super::truncate(&line, 55))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Nntp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command() {
        let r = dissect_nntp(None, None, 40000, 119, b"GROUP comp.lang.rust\r\n");
        assert_eq!(r.protocol, Protocol::Nntp);
        assert!(r.summary.starts_with("NNTP — GROUP"), "{}", r.summary);
    }

    #[test]
    fn response_code() {
        let r = dissect_nntp(None, None, 119, 40000, b"200 news.example.com ready\r\n");
        assert!(r.summary.starts_with("NNTP Response — 200"));
    }
}
