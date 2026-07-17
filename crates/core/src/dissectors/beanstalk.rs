// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Known beanstalkd command/response keywords, used to confirm the first token
/// is protocol traffic rather than arbitrary text.
const KEYWORDS: [&str; 16] = [
    "put",
    "reserve",
    "delete",
    "release",
    "bury",
    "watch",
    "ignore",
    "use",
    "peek",
    "kick",
    "stats",
    "INSERTED",
    "RESERVED",
    "DELETED",
    "BURIED",
    "OK",
];

/// Dissect a beanstalkd message (TCP 11300) — a simple work queue. It's a
/// line-based text protocol (put / reserve / delete …).
pub fn dissect_beanstalk(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let line = super::first_text_line(payload);
    let tok = line.split_whitespace().next().unwrap_or("");
    let summary = if KEYWORDS.contains(&tok) {
        format!("Beanstalk {tok}")
    } else if line.is_empty() {
        format!("Beanstalk ({} bytes)", payload.len())
    } else {
        format!("Beanstalk — {}", super::truncate(&line, 40))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Beanstalk,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_command() {
        let r = dissect_beanstalk(None, None, 40000, 11300, b"put 0 0 60 5\r\nhello\r\n");
        assert_eq!(r.protocol, Protocol::Beanstalk);
        assert_eq!(r.summary, "Beanstalk put");
    }
}
