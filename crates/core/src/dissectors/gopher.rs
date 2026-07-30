// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Gopher message (TCP 70) — the pre-web document protocol. A client
/// sends a selector line; the server returns a menu whose lines each start with
/// an item-type character (RFC 1436).
pub fn dissect_gopher(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let line = super::first_text_line(payload);
    let summary = if line.is_empty() {
        "Gopher — root menu request".to_string()
    } else if line.contains('\t') {
        // Menu entries are tab-separated: type+display, selector, host, port.
        format!("Gopher menu — {}", super::truncate(&line, 48))
    } else {
        format!("Gopher — selector {}", super::truncate(&line, 40))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Gopher,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_request() {
        let r = dissect_gopher(None, None, 40000, 70, b"\r\n");
        assert_eq!(r.protocol, Protocol::Gopher);
        assert_eq!(r.summary, "Gopher — root menu request");
    }

    #[test]
    fn selector() {
        let r = dissect_gopher(None, None, 40000, 70, b"/docs/readme\r\n");
        assert!(r.summary.contains("/docs/readme"), "{}", r.summary);
    }
}
