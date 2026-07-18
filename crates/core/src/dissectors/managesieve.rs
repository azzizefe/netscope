// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a ManageSieve message (TCP 4190) — how a mail client uploads and
/// manages server-side Sieve filtering scripts. It's a line-based text
/// protocol (RFC 5804).
pub fn dissect_managesieve(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let line = super::first_text_line(payload);
    let token = line
        .trim_matches('"')
        .split_whitespace()
        .next()
        .unwrap_or("");
    let summary = match token.trim_matches('"') {
        "" => format!("ManageSieve ({} bytes)", payload.len()),
        "OK" | "NO" | "BYE" => format!("ManageSieve {token} response"),
        t if t.eq_ignore_ascii_case("IMPLEMENTATION") => {
            format!("ManageSieve greeting — {}", super::truncate(&line, 40))
        }
        t => format!("ManageSieve {}", t.to_uppercase()),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::ManageSieve,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_script() {
        let r = dissect_managesieve(None, None, 40000, 4190, b"PUTSCRIPT \"myfilter\" {12+}\r\n");
        assert_eq!(r.protocol, Protocol::ManageSieve);
        assert_eq!(r.summary, "ManageSieve PUTSCRIPT");
    }

    #[test]
    fn greeting() {
        let r = dissect_managesieve(
            None,
            None,
            4190,
            40000,
            b"\"IMPLEMENTATION\" \"Dovecot\"\r\n",
        );
        assert!(
            r.summary.starts_with("ManageSieve greeting"),
            "{}",
            r.summary
        );
    }
}
