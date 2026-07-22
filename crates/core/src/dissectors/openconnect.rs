// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an OpenConnect / Cisco AnyConnect SSL VPN CSTP packet.
pub fn dissect_openconnect(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        format!("OpenConnect SSL VPN ({})", super::bytes(payload.len() as u64))
    } else {
        let text = String::from_utf8_lossy(payload);
        if text.contains("CONNECT /") || text.contains("X-CSTP-") {
            "OpenConnect / AnyConnect CSTP Handshake".to_string()
        } else {
            let ptype = payload[4];
            let name = match ptype {
                0x00 => "DATA",
                0x03 => "KEEPALIVE",
                0x04 => "DISCONNECT",
                _ => "CSTP Frame",
            };
            format!("OpenConnect CSTP {name}")
        }
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Openconnect,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openconnect_handshake() {
        let payload = b"CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\nX-CSTP-Version: 1\r\n";
        let res = dissect_openconnect(None, None, 443, 443, payload);
        assert_eq!(res.protocol, Protocol::Openconnect);
        assert!(res.summary.contains("CSTP Handshake"));
    }

    #[test]
    fn test_openconnect_short_payload() {
        let payload = vec![0x00, 0x01];
        let res = dissect_openconnect(None, None, 443, 443, &payload);
        assert_eq!(res.protocol, Protocol::Openconnect);
        assert!(res.summary.contains("OpenConnect SSL VPN (2 bytes)"));
    }
}
