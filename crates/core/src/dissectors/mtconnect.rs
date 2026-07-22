// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect MTConnect industrial machine tool telemetry protocol (TCP 5000 / HTTP REST XML).
pub fn dissect_mtconnect(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if let Ok(s) = std::str::from_utf8(payload) {
        if s.contains("MTConnectStreams") {
            "MTConnect Telemetry Stream".into()
        } else if s.contains("MTConnectDevices") {
            "MTConnect Device Description".into()
        } else if s.contains("MTConnectAssets") {
            "MTConnect Asset Data".into()
        } else if s.contains("GET /probe") {
            "MTConnect Probe Request".into()
        } else if s.contains("GET /current") || s.contains("GET /sample") {
            "MTConnect Sample Request".into()
        } else {
            format!("MTConnect ({})", super::bytes(payload.len() as u64))
        }
    } else {
        format!("MTConnect ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Mtconnect,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mtconnect_sample() {
        let payload = b"GET /sample?from=100 HTTP/1.1\r\nHost: cnc-machine:5000\r\n\r\n";
        let r = dissect_mtconnect(None, None, 40000, 5000, payload);
        assert_eq!(r.protocol, Protocol::Mtconnect);
        assert_eq!(r.summary, "MTConnect Sample Request");
    }
}
