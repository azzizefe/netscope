// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect Zipkin Span Reporting HTTP API (TCP 9411).
pub fn dissect_zipkin(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"POST /api/v2/spans") || payload.starts_with(b"POST /api/v1/spans") {
        "Zipkin span report".to_string()
    } else {
        format!("Zipkin API ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Zipkin,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zipkin_test() {
        let r = dissect_zipkin(None, None, 40000, 9411, b"POST /api/v2/spans HTTP/1.1\r\n");
        assert_eq!(r.protocol, Protocol::Zipkin);
        assert_eq!(r.summary, "Zipkin span report");
    }
}
