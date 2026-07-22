// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a GUE (Generic UDP Encapsulation — RFC 8154) packet (UDP 6080).
pub fn dissect_gue(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        format!("GUE ({})", super::bytes(payload.len() as u64))
    } else {
        let ver = (payload[0] & 0xC0) >> 6;
        let proto = payload[1];
        let hlen = (payload[0] & 0x1F) as usize * 4;

        let proto_desc = match proto {
            4 => "IPv4 Encapsulation",
            41 => "IPv6 Encapsulation",
            47 => "GRE Encapsulation",
            _ => "Generic Encapsulation",
        };

        format!("GUE v{ver} — {proto_desc} (IP Proto {proto}, Header {hlen}B)")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Gue,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gue_ipv4() {
        // Ver = 0, Hlen = 1 (4B), Proto = 4 (IPv4)
        let payload = vec![0x01, 0x04, 0x00, 0x00];
        let res = dissect_gue(None, None, 6080, 6080, &payload);
        assert_eq!(res.protocol, Protocol::Gue);
        assert!(res.summary.contains("IPv4 Encapsulation"));
    }

    #[test]
    fn test_gue_short_payload() {
        let payload = vec![0x01, 0x02];
        let res = dissect_gue(None, None, 6080, 6080, &payload);
        assert_eq!(res.protocol, Protocol::Gue);
        assert!(res.summary.contains("GUE (2 bytes)"));
    }
}
