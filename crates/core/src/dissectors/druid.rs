// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect Apache Druid HTTP ingest & query API (TCP 8888 / 8082).
pub fn dissect_druid(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"POST /druid/v2/sql") {
        "Druid SQL query".to_string()
    } else if payload.starts_with(b"POST /druid/v2") {
        "Druid native query".to_string()
    } else {
        format!("Druid HTTP API ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Druid,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn druid_sql() {
        let r = dissect_druid(None, None, 40000, 8888, b"POST /druid/v2/sql HTTP/1.1\r\n");
        assert_eq!(r.protocol, Protocol::Druid);
        assert_eq!(r.summary, "Druid SQL query");
    }
}
