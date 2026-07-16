// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Memcached message (TCP 11211). Memcached speaks either a simple
/// text protocol (`get`, `set`, `STORED`…) or a binary protocol whose requests
/// start with 0x80 and responses with 0x81.
pub fn dissect_memcached(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.first() {
        Some(0x80) => "Memcached binary request".to_string(),
        Some(0x81) => "Memcached binary response".to_string(),
        _ => {
            let line = super::first_text_line(payload);
            let word = line.split_whitespace().next().unwrap_or("");
            if word.is_empty() {
                format!("Memcached ({} bytes)", payload.len())
            } else {
                format!("Memcached {word} — {}", super::truncate(&line, 50))
            }
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Memcached,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_get() {
        let r = dissect_memcached(None, None, 40000, 11211, b"get session:42\r\n");
        assert_eq!(r.protocol, Protocol::Memcached);
        assert!(r.summary.starts_with("Memcached get —"), "{}", r.summary);
    }

    #[test]
    fn binary_request() {
        let r = dissect_memcached(None, None, 40000, 11211, &[0x80, 0x00, 0x00, 0x03]);
        assert_eq!(r.summary, "Memcached binary request");
    }
}
