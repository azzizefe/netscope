// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect Trino / Presto HTTP query REST API (TCP 8080 / 8443).
pub fn dissect_trino(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"POST /v1/statement") {
        "Trino/Presto SQL query submission".to_string()
    } else if payload.starts_with(b"GET /v1/query") {
        "Trino/Presto query status request".to_string()
    } else {
        format!("Trino/Presto protocol ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Trino,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trino_post() {
        let r = dissect_trino(None, None, 40000, 8080, b"POST /v1/statement HTTP/1.1\r\n");
        assert_eq!(r.protocol, Protocol::Trino);
        assert!(r.summary.contains("query submission"));
    }
}
