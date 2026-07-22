// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect Grafana Loki Log Push API (TCP 3100).
pub fn dissect_loki_push(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"POST /loki/api/v1/push") {
        "Loki log push".to_string()
    } else {
        format!("Loki HTTP API ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::LokiPush,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loki_test() {
        let r = dissect_loki_push(None, None, 40000, 3100, b"POST /loki/api/v1/push HTTP/1.1\r\n");
        assert_eq!(r.protocol, Protocol::LokiPush);
        assert_eq!(r.summary, "Loki log push");
    }
}
