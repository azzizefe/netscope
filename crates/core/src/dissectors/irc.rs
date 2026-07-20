// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an IRC message (TCP 6667). Each line is an optional `:prefix`,
/// a command (or 3-digit numeric reply), then parameters (RFC 1459).
pub fn dissect_irc(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let line = super::first_text_line(payload);
    // Strip an optional `:prefix ` before reading the command word.
    let body = line
        .strip_prefix(':')
        .and_then(|rest| rest.split_once(' ').map(|(_, r)| r))
        .unwrap_or(&line);
    let command = body.split_whitespace().next().unwrap_or("");
    let summary = if command.is_empty() {
        format!("IRC ({})", super::bytes(payload.len() as u64))
    } else {
        format!("IRC {command} — {}", super::truncate(&line, 50))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Irc,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privmsg_with_prefix() {
        let r = dissect_irc(
            None,
            None,
            40000,
            6667,
            b":nick!user@host PRIVMSG #chan :hello\r\n",
        );
        assert_eq!(r.protocol, Protocol::Irc);
        assert!(r.summary.starts_with("IRC PRIVMSG —"), "{}", r.summary);
    }

    #[test]
    fn bare_command() {
        let r = dissect_irc(None, None, 40000, 6667, b"NICK alice\r\n");
        assert!(r.summary.starts_with("IRC NICK —"));
    }
}
