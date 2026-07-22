// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect Netdata Streaming Protocol (TCP 19999).
pub fn dissect_netdata(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"STREAM ") {
        "Netdata STREAM handshake".to_string()
    } else {
        format!("Netdata Stream ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Netdata,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netdata_test() {
        let r = dissect_netdata(None, None, 40000, 19999, b"STREAM machine_guid=xyz\n");
        assert_eq!(r.protocol, Protocol::Netdata);
        assert!(r.summary.contains("handshake"));
    }
}
