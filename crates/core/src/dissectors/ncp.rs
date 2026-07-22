// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Novell NetWare Core Protocol (NCP, TCP/UDP 524 or IPX socket 0x0451) frame.
pub fn dissect_ncp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 2 {
        let req_type = u16::from_be_bytes([payload[0], payload[1]]);
        let name = match req_type {
            0x1111 => "Create Session",
            0x2222 => "Request",
            0x3333 => "Reply",
            0x5555 => "Destroy Session",
            0x7777 => "Burst",
            0x9999 => "Ping",
            _ => "Message",
        };
        format!("Novell NCP {name}")
    } else {
        format!("Novell NCP ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ncp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ncp_request() {
        let payload = vec![0x22, 0x22, 0x01, 0x00];
        let r = dissect_ncp(None, None, 40000, 524, &payload);
        assert_eq!(r.protocol, Protocol::Ncp);
        assert_eq!(r.summary, "Novell NCP Request");
    }
}
