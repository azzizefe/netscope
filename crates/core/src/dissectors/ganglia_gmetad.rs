// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect Ganglia gmetad interactive XML protocol (TCP 8651).
pub fn dissect_ganglia_gmetad(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"<GANGLIA_XML") || payload.starts_with(b"<?xml") {
        "Ganglia gmetad XML export".to_string()
    } else {
        format!("Ganglia gmetad ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::GangliaGmetad,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ganglia_gmetad_test() {
        let r = dissect_ganglia_gmetad(None, None, 40000, 8651, b"<GANGLIA_XML VERSION=\"3.0\">\n");
        assert_eq!(r.protocol, Protocol::GangliaGmetad);
        assert!(r.summary.contains("XML export"));
    }
}
