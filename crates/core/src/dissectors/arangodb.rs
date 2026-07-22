// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect ArangoDB VelocyStream binary / HTTP REST API (TCP 8529).
pub fn dissect_arangodb(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"VST/") {
        "ArangoDB VelocyStream binary header".to_string()
    } else if payload.starts_with(b"GET ") || payload.starts_with(b"POST ") {
        "ArangoDB HTTP REST request".to_string()
    } else {
        format!("ArangoDB protocol ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::ArangoDb,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arangodb_vst() {
        let r = dissect_arangodb(None, None, 40000, 8529, b"VST/1.1");
        assert_eq!(r.protocol, Protocol::ArangoDb);
        assert!(r.summary.contains("VelocyStream"));
    }
}
