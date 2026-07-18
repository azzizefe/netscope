// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Gearman message (TCP 4730) — a job queue distributing work to
/// workers. Binary packets start with "\0REQ" (request) or "\0RES" (response);
/// admin commands are plain text.
pub fn dissect_gearman(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"\0REQ") {
        "Gearman request".to_string()
    } else if payload.starts_with(b"\0RES") {
        "Gearman response".to_string()
    } else {
        let line = super::first_text_line(payload);
        if line.is_empty() {
            format!("Gearman ({} bytes)", payload.len())
        } else {
            format!("Gearman admin — {}", super::truncate(&line, 40))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Gearman,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request() {
        let r = dissect_gearman(None, None, 40000, 4730, b"\0REQ\x00\x00\x00\x07");
        assert_eq!(r.protocol, Protocol::Gearman);
        assert_eq!(r.summary, "Gearman request");
    }
}
