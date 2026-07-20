// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{first_text_line, truncate, DissectedResult};

/// Dissect a POP3 segment (TCP 110). Line-oriented: client commands
/// (`USER alice`, `RETR 1`) and `+OK` / `-ERR` server replies. The `PASS`
/// argument is masked.
pub fn dissect_pop3(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let line = first_text_line(payload);
    let summary = if line.is_empty() {
        format!("POP3 — {}", super::bytes(payload.len() as u64))
    } else if line.len() >= 4 && line[..4].eq_ignore_ascii_case("PASS") {
        "POP3 PASS ⋯".into()
    } else {
        format!("POP3 {}", truncate(&line, 50))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Pop3,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_command() {
        let r = dissect_pop3(None, None, 40000, 110, b"USER alice\r\n");
        assert_eq!(r.protocol, Protocol::Pop3);
        assert_eq!(r.summary, "POP3 USER alice");
    }

    #[test]
    fn password_is_masked() {
        let r = dissect_pop3(None, None, 40000, 110, b"PASS hunter2\r\n");
        assert_eq!(r.summary, "POP3 PASS ⋯");
    }

    #[test]
    fn ok_reply() {
        let r = dissect_pop3(None, None, 110, 40000, b"+OK POP3 ready\r\n");
        assert_eq!(r.summary, "POP3 +OK POP3 ready");
    }
}
