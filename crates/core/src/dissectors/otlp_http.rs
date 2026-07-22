// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect OpenTelemetry OTLP over HTTP (TCP 4318).
pub fn dissect_otlp_http(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"POST /v1/traces") {
        "OTLP HTTP traces export".to_string()
    } else if payload.starts_with(b"POST /v1/metrics") {
        "OTLP HTTP metrics export".to_string()
    } else if payload.starts_with(b"POST /v1/logs") {
        "OTLP HTTP logs export".to_string()
    } else {
        format!("OTLP HTTP ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::OtlpHttp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn otlp_http_test() {
        let r = dissect_otlp_http(None, None, 40000, 4318, b"POST /v1/traces HTTP/1.1\r\n");
        assert_eq!(r.protocol, Protocol::OtlpHttp);
        assert_eq!(r.summary, "OTLP HTTP traces export");
    }
}
