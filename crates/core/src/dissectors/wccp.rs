// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a WCCP message (UDP 2048) — how a router hands web traffic to a
/// cache/proxy. The first four bytes are the WCCP2 message type.
pub fn dissect_wccp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        let msg = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let name = match msg {
            10 => "Here-I-Am",
            11 => "I-See-You",
            12 => "Redirect-Assign",
            13 => "Removal-Query",
            _ => "message",
        };
        format!("WCCP {name}")
    } else {
        "WCCP (truncated)".to_string()
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Wccp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn here_i_am() {
        let r = dissect_wccp(None, None, 2048, 2048, &[0x00, 0x00, 0x00, 0x0A]);
        assert_eq!(r.protocol, Protocol::Wccp);
        assert_eq!(r.summary, "WCCP Here-I-Am");
    }
}
