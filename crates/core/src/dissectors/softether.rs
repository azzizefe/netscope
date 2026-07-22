// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a SoftEther VPN protocol packet.
pub fn dissect_softether(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.is_empty() {
        format!("SoftEther ({})", super::bytes(0u64))
    } else {
        let text = String::from_utf8_lossy(payload);
        if text.contains("SEVP") || text.contains("SoftEther") {
            "SoftEther VPN Protocol Session".to_string()
        } else if text.contains("POST /vpn/") || text.contains("GET /vpn/") {
            "SoftEther VPN HTTPS Tunnel".to_string()
        } else {
            format!("SoftEther VPN Frame ({})", super::bytes(payload.len() as u64))
        }
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SoftEther,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_softether_tunnel() {
        let payload = b"POST /vpn/ HTTP/1.1\r\nHost: softether\r\n";
        let res = dissect_softether(None, None, 443, 443, payload);
        assert_eq!(res.protocol, Protocol::SoftEther);
        assert!(res.summary.contains("SoftEther VPN HTTPS Tunnel"));
    }

    #[test]
    fn test_softether_empty_payload() {
        let payload = vec![];
        let res = dissect_softether(None, None, 443, 443, &payload);
        assert_eq!(res.protocol, Protocol::SoftEther);
        assert!(res.summary.contains("SoftEther (0 bytes)"));
    }
}
