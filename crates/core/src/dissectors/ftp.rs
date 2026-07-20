// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{first_text_line, truncate, DissectedResult};

/// Dissect an FTP control-channel segment (TCP 21). FTP is line-oriented:
/// client commands (`USER alice`, `RETR file`) and 3-digit server replies
/// (`220 Service ready`). The `PASS` argument is masked so a cleartext
/// password isn't echoed into the packet list.
pub fn dissect_ftp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let line = first_text_line(payload);
    let summary = if is_reply_code(&line) {
        format!("FTP {}", truncate(&line, 50))
    } else if line.len() >= 4 && line[..4].eq_ignore_ascii_case("PASS") {
        "FTP PASS ⋯".into()
    } else if line.is_empty() {
        format!("FTP — {}", super::bytes(payload.len() as u64))
    } else {
        format!("FTP {}", truncate(&line, 50))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ftp,
        summary,
    }
}

/// A reply line begins with a 3-digit status code.
fn is_reply_code(line: &str) -> bool {
    let b = line.as_bytes();
    b.len() >= 3 && b[..3].iter().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_command() {
        let r = dissect_ftp(None, None, 40000, 21, b"USER alice\r\n");
        assert_eq!(r.protocol, Protocol::Ftp);
        assert_eq!(r.summary, "FTP USER alice");
    }

    #[test]
    fn password_is_masked() {
        let r = dissect_ftp(None, None, 40000, 21, b"PASS hunter2\r\n");
        assert_eq!(r.summary, "FTP PASS ⋯");
    }

    #[test]
    fn server_reply() {
        let r = dissect_ftp(None, None, 21, 40000, b"220 Service ready\r\n");
        assert_eq!(r.summary, "FTP 220 Service ready");
    }
}
