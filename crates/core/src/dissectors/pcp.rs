// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a PCP or NAT-PMP message (UDP 5351) — how an application asks the
/// home router to open an inbound port for it. Byte 0 is the version: 0 is the
/// older NAT-PMP, 2 is Port Control Protocol (RFC 6887).
pub fn dissect_pcp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match (payload.first(), payload.get(1)) {
        (Some(0), Some(&op)) => {
            let name = match op {
                0 => "external address request",
                1 => "map UDP",
                2 => "map TCP",
                128 => "external address response",
                _ => "message",
            };
            format!("NAT-PMP {name}")
        }
        (Some(2), Some(&op)) => {
            // The top bit of the opcode byte marks a response.
            let is_response = op & 0x80 != 0;
            let name = match op & 0x7F {
                0 => "ANNOUNCE",
                1 => "MAP",
                2 => "PEER",
                _ => "opcode",
            };
            let dir = if is_response { "response" } else { "request" };
            format!("PCP {name} {dir}")
        }
        _ => format!("PCP/NAT-PMP ({})", super::bytes(payload.len() as u64)),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Pcp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcp_map_request() {
        let r = dissect_pcp(None, None, 40000, 5351, &[0x02, 0x01, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Pcp);
        assert_eq!(r.summary, "PCP MAP request");
    }

    #[test]
    fn natpmp_map_tcp() {
        let r = dissect_pcp(None, None, 40000, 5351, &[0x00, 0x02, 0x00, 0x00]);
        assert!(r.summary.contains("map TCP"), "{}", r.summary);
    }
}
