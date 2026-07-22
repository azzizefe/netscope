// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect VictoriaMetrics ingestion protocol (TCP 8428).
pub fn dissect_victoriametrics(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"POST /api/v1/import") {
        "VictoriaMetrics batch import".to_string()
    } else if payload.starts_with(b"POST /api/v1/write") {
        "VictoriaMetrics Prometheus write".to_string()
    } else {
        format!("VictoriaMetrics ingestion ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::VictoriaMetrics,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn victoriametrics_import() {
        let r = dissect_victoriametrics(None, None, 40000, 8428, b"POST /api/v1/import HTTP/1.1\r\n");
        assert_eq!(r.protocol, Protocol::VictoriaMetrics);
        assert_eq!(r.summary, "VictoriaMetrics batch import");
    }
}
