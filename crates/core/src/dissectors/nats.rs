// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a NATS message (TCP 4222) — a lightweight cloud-native messaging
/// system. It's a simple text protocol: INFO, CONNECT, PUB, SUB, MSG, PING…
pub fn dissect_nats(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let line = super::first_text_line(payload);
    let verb = line.split_whitespace().next().unwrap_or("");
    let summary = if verb.is_empty() {
        format!("NATS ({})", super::bytes(payload.len() as u64))
    } else {
        format!("NATS {verb} — {}", super::truncate(&line, 48))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Nats,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish() {
        let r = dissect_nats(None, None, 40000, 4222, b"PUB events.orders 12\r\n");
        assert_eq!(r.protocol, Protocol::Nats);
        assert!(r.summary.starts_with("NATS PUB —"), "{}", r.summary);
    }
}
