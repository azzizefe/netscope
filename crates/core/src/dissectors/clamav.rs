// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a ClamAV daemon message (TCP 3310) — mail and file gateways handing
/// content to clamd for virus scanning. Commands are text, optionally prefixed
/// with `z` (NUL-terminated) or `n` (newline-terminated).
pub fn dissect_clamav(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    // clamd commands are NUL- or newline-terminated, and NUL is not whitespace,
    // so strip it explicitly before reading the verb.
    let line = super::first_text_line(payload)
        .trim_matches(|c: char| c == '\0' || c.is_whitespace())
        .to_string();
    let cmd = line
        .trim_start_matches(['z', 'n'])
        .split_whitespace()
        .next()
        .unwrap_or("");
    let summary = if line.contains("FOUND") {
        format!("ClamAV — {} (threat detected)", super::truncate(&line, 48))
    } else if !cmd.is_empty() && cmd.chars().all(|c| c.is_ascii_uppercase()) {
        format!("ClamAV {cmd}")
    } else {
        format!("ClamAV scan data ({})", super::bytes(payload.len() as u64))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Clamav,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instream_command() {
        let r = dissect_clamav(None, None, 40000, 3310, b"zINSTREAM\0");
        assert_eq!(r.protocol, Protocol::Clamav);
        assert_eq!(r.summary, "ClamAV INSTREAM");
    }

    #[test]
    fn detection_is_called_out() {
        let r = dissect_clamav(
            None,
            None,
            3310,
            40000,
            b"stream: Eicar-Test-Signature FOUND\n",
        );
        assert!(r.summary.contains("threat detected"), "{}", r.summary);
    }
}
