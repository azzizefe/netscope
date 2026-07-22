// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a 6to4 IPv6 in IPv4 encapsulation (RFC 3056 / IP Proto 41).
pub fn dissect_six_to_four(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 40 {
        format!("6to4 Tunnel ({})", super::bytes(payload.len() as u64))
    } else {
        let ver = (payload[0] & 0xF0) >> 4;
        if ver == 6 {
            let src_bytes = &payload[8..24];
            if src_bytes[0] == 0x20 && src_bytes[1] == 0x02 {
                let ipv4_addr = format!("{}.{}.{}.{}", src_bytes[2], src_bytes[3], src_bytes[4], src_bytes[5]);
                format!("6to4 IPv6 Tunnel — 2002::{ipv4_addr}")
            } else {
                "6to4 IPv6 Encapsulated Tunnel".to_string()
            }
        } else {
            "6to4 Tunnel".to_string()
        }
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: None,
        dst_port: None,
        protocol: Protocol::SixToFour,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_six_to_four_tunnel() {
        let mut payload = vec![0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x06, 0x40];
        // Src IP = 2002:c000:0201::1 (192.0.2.1)
        payload.extend_from_slice(&[0x20, 0x02, 192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // Dst IP = 2001:db8::2
        payload.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        payload.resize(40, 0);

        let res = dissect_six_to_four(None, None, &payload);
        assert_eq!(res.protocol, Protocol::SixToFour);
        assert!(res.summary.contains("2002::192.0.2.1"));
    }

    #[test]
    fn test_six_to_four_short_payload() {
        let payload = vec![0x01, 0x02];
        let res = dissect_six_to_four(None, None, &payload);
        assert_eq!(res.protocol, Protocol::SixToFour);
        assert!(res.summary.contains("6to4 Tunnel (2 bytes)"));
    }
}
