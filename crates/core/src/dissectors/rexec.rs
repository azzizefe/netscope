// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an rexec message (TCP 512) — the BSD remote-execution service. The
/// client sends NUL-separated fields: stderr port, username, **password** and
/// the command. Unlike rsh it authenticates, but it does so in cleartext, so
/// any capture of it exposes credentials.
pub fn dissect_rexec(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let fields: Vec<String> = payload
        .split(|&b| b == 0)
        .take(4)
        .map(|f| String::from_utf8_lossy(f).trim().to_string())
        .collect();
    // [stderr_port, username, password, command]
    let summary = match (fields.get(1), fields.get(3)) {
        (Some(user), Some(cmd)) if !user.is_empty() && !cmd.is_empty() => format!(
            "rexec — {} runs \"{}\" (cleartext password)",
            super::truncate(user, 20),
            super::truncate(cmd, 28)
        ),
        _ => {
            let line = super::first_text_line(payload);
            if line.is_empty() {
                format!("rexec session data ({} bytes)", payload.len())
            } else {
                format!("rexec — {}", super::truncate(&line, 40))
            }
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Rexec,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_credentials_in_the_clear() {
        let r = dissect_rexec(None, None, 1023, 512, b"0\0alice\0hunter2\0uptime\0");
        assert_eq!(r.protocol, Protocol::Rexec);
        assert!(r.summary.contains("alice"), "{}", r.summary);
        assert!(r.summary.contains("cleartext password"), "{}", r.summary);
    }
}
