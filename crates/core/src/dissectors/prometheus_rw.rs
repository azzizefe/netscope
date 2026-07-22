// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect Prometheus remote-write Snappy-compressed protobuf payload (TCP 9090 / 9201).
pub fn dissect_prometheus_rw(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"POST /api/v1/write") || payload.starts_with(b"POST /receive") {
        "Prometheus remote-write push".to_string()
    } else {
        format!("Prometheus remote-write payload ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::PrometheusRw,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prometheus_rw_push() {
        let r = dissect_prometheus_rw(None, None, 40000, 9090, b"POST /api/v1/write HTTP/1.1\r\n");
        assert_eq!(r.protocol, Protocol::PrometheusRw);
        assert_eq!(r.summary, "Prometheus remote-write push");
    }
}
