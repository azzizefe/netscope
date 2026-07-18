// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an Elasticsearch transport message (TCP 9300) — the internal binary
/// protocol nodes use to talk to each other (distinct from the HTTP API on
/// 9200). Each message starts with the marker bytes 'E','S'.
pub fn dissect_elasticsearch(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"ES") {
        "Elasticsearch transport message".to_string()
    } else {
        format!("Elasticsearch transport ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Elasticsearch,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_message() {
        let r = dissect_elasticsearch(None, None, 40000, 9300, b"ES\x00\x00\x00\x10");
        assert_eq!(r.protocol, Protocol::Elasticsearch);
        assert_eq!(r.summary, "Elasticsearch transport message");
    }
}
