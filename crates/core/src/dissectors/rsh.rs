// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an rsh message (TCP 514) — the BSD remote-shell service. The client
/// opens with NUL-separated fields: stderr port, local user, remote user and
/// the command to run. Everything is cleartext and host-trust based, so like
/// rlogin it was superseded by SSH (RFC 1282 family).
pub fn dissect_rsh(
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
    // A startup record looks like ["", localuser, remoteuser, command] or
    // ["stderrport", localuser, remoteuser, command].
    let summary = match (fields.get(1), fields.get(3)) {
        (Some(user), Some(cmd)) if !user.is_empty() && !cmd.is_empty() => {
            format!(
                "rsh — {} runs \"{}\"",
                super::truncate(user, 20),
                super::truncate(cmd, 32)
            )
        }
        _ => {
            let line = super::first_text_line(payload);
            if line.is_empty() {
                format!("rsh session data ({})", super::bytes(payload.len() as u64))
            } else {
                format!("rsh — {}", super::truncate(&line, 40))
            }
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Rsh,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_startup() {
        let r = dissect_rsh(None, None, 1023, 514, b"0\0alice\0bob\0cat /etc/passwd\0");
        assert_eq!(r.protocol, Protocol::Rsh);
        assert!(r.summary.contains("alice"), "{}", r.summary);
        assert!(r.summary.contains("cat /etc/passwd"), "{}", r.summary);
    }
}
