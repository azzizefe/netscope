// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an ISATAP (Intra-Site Automatic Tunnel Addressing Protocol — RFC 5214) packet.
pub fn dissect_isatap(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 40 {
        format!("ISATAP Tunnel ({})", super::bytes(payload.len() as u64))
    } else {
        let src_bytes = &payload[8..24];
        let is_isatap_iid = src_bytes[8] == 0x00 && src_bytes[9] == 0x00 && src_bytes[10] == 0x5E && src_bytes[11] == 0xFE;
        if is_isatap_iid {
            let ipv4_addr = format!("{}.{}.{}.{}", src_bytes[12], src_bytes[13], src_bytes[14], src_bytes[15]);
            format!("ISATAP IPv6 Tunnel — fe80::5efe:{ipv4_addr}")
        } else {
            "ISATAP Automatic Tunnel".to_string()
        }
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Isatap,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isatap_tunnel() {
        let mut payload = vec![0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x06, 0x40];
        // Src IP = fe80::0000:5efe:192.168.1.10
        payload.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x5e, 0xfe, 192, 168, 1, 10]);
        // Dst IP
        payload.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        payload.resize(40, 0);

        let res = dissect_isatap(None, None, &payload);
        assert_eq!(res.protocol, Protocol::Isatap);
        assert!(res.summary.contains("fe80::5efe:192.168.1.10"));
    }

    #[test]
    fn test_isatap_short_payload() {
        let payload = vec![0x01, 0x02];
        let res = dissect_isatap(None, None, &payload);
        assert_eq!(res.protocol, Protocol::Isatap);
        assert!(res.summary.contains("ISATAP Tunnel (2 bytes)"));
    }
}
