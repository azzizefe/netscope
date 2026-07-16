// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// RTSP request methods (RFC 2326) used to label the request line.
const METHODS: [&str; 11] = [
    "OPTIONS",
    "DESCRIBE",
    "ANNOUNCE",
    "SETUP",
    "PLAY",
    "PAUSE",
    "TEARDOWN",
    "GET_PARAMETER",
    "SET_PARAMETER",
    "RECORD",
    "REDIRECT",
];

/// Dissect an RTSP message (TCP 554) — the control channel for streaming
/// media. Requests start with a method; responses start with `RTSP/1.0`.
pub fn dissect_rtsp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let line = super::first_text_line(payload);
    let summary = if line.starts_with("RTSP/") {
        format!("RTSP Response — {}", super::truncate(&line, 50))
    } else if let Some(method) = line.split_whitespace().next().filter(|m| METHODS.contains(m)) {
        format!("RTSP {method} — {}", super::truncate(&line, 50))
    } else if line.is_empty() {
        format!("RTSP ({} bytes)", payload.len())
    } else {
        format!("RTSP — {}", super::truncate(&line, 50))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Rtsp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_request() {
        let r = dissect_rtsp(None, None, 40000, 554, b"DESCRIBE rtsp://cam/stream RTSP/1.0\r\n");
        assert_eq!(r.protocol, Protocol::Rtsp);
        assert!(r.summary.starts_with("RTSP DESCRIBE —"), "{}", r.summary);
    }

    #[test]
    fn response() {
        let r = dissect_rtsp(None, None, 554, 40000, b"RTSP/1.0 200 OK\r\n");
        assert!(r.summary.starts_with("RTSP Response —"));
    }
}
