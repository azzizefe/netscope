// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{first_text_line, truncate, DissectedResult};

/// Dissect an SMTP segment (TCP 25/587). Line-oriented: client commands
/// (`HELO`, `MAIL FROM:<…>`, `RCPT TO:<…>`, `DATA`) and 3-digit server
/// replies (`250 OK`). Credentials after `AUTH` are masked.
pub fn dissect_smtp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let line = first_text_line(payload);
    let summary = if line.is_empty() {
        format!("SMTP — {}", super::bytes(payload.len() as u64))
    } else if line.len() >= 4 && line[..4].eq_ignore_ascii_case("AUTH") {
        "SMTP AUTH ⋯".into()
    } else {
        format!("SMTP {}", truncate(&line, 50))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Smtp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mail_from_command() {
        let r = dissect_smtp(None, None, 40000, 25, b"MAIL FROM:<a@b.com>\r\n");
        assert_eq!(r.protocol, Protocol::Smtp);
        assert_eq!(r.summary, "SMTP MAIL FROM:<a@b.com>");
    }

    #[test]
    fn server_greeting() {
        let r = dissect_smtp(None, None, 25, 40000, b"250 OK\r\n");
        assert_eq!(r.summary, "SMTP 250 OK");
    }

    #[test]
    fn auth_is_masked() {
        let r = dissect_smtp(None, None, 40000, 587, b"AUTH LOGIN dXNlcg==\r\n");
        assert_eq!(r.summary, "SMTP AUTH ⋯");
    }
}
