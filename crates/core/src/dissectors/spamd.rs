// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a SpamAssassin spamd message (TCP 783) — a mail server asking the
/// spam filter to score a message. Requests are `COMMAND SPAMC/1.5`; replies
/// start `SPAMD/1.5`.
pub fn dissect_spamd(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let line = super::first_text_line(payload);
    let summary = if line.starts_with("SPAMD/") {
        format!("spamd response — {}", super::truncate(&line, 40))
    } else {
        match line.split_whitespace().next() {
            Some(cmd) if line.contains("SPAMC/") => format!("spamd {cmd} request"),
            _ => format!(
                "spamd message data ({})",
                super::bytes(payload.len() as u64)
            ),
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Spamd,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_request() {
        let r = dissect_spamd(None, None, 40000, 783, b"CHECK SPAMC/1.5\r\n");
        assert_eq!(r.protocol, Protocol::Spamd);
        assert_eq!(r.summary, "spamd CHECK request");
    }

    #[test]
    fn response() {
        let r = dissect_spamd(None, None, 783, 40000, b"SPAMD/1.5 0 EX_OK\r\n");
        assert!(r.summary.starts_with("spamd response"), "{}", r.summary);
    }
}
