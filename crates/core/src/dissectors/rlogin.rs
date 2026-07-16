// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an rlogin message (TCP 513) — a legacy BSD remote-login service.
/// The session opens with NUL-separated fields (local user, remote user,
/// terminal/speed); everything is cleartext (RFC 1282).
pub fn dissect_rlogin(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    // The startup record begins with a NUL byte followed by the login fields.
    let summary = if payload.first() == Some(&0) && payload.len() > 1 {
        let fields: Vec<String> = payload[1..]
            .split(|&b| b == 0)
            .take(2)
            .filter(|f| !f.is_empty())
            .map(|f| String::from_utf8_lossy(f).into_owned())
            .collect();
        if fields.is_empty() {
            "rlogin — session start".to_string()
        } else {
            format!("rlogin — login {}", super::truncate(&fields.join("/"), 40))
        }
    } else {
        let line = super::first_text_line(payload);
        if line.is_empty() {
            format!("rlogin ({} bytes)", payload.len())
        } else {
            format!("rlogin — {}", super::truncate(&line, 40))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Rlogin,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_fields() {
        let r = dissect_rlogin(None, None, 40000, 513, b"\0alice\0bob\0xterm/38400\0");
        assert_eq!(r.protocol, Protocol::Rlogin);
        assert!(r.summary.contains("alice/bob"), "{}", r.summary);
    }
}
