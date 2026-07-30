// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a NetFlow / IPFIX export (UDP 2055/4739/9995) — routers and
/// switches reporting traffic-flow statistics to a collector. The first two
/// bytes are the version (RFC 3954 / RFC 7011).
pub fn dissect_netflow(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 2 {
        let version = u16::from_be_bytes([payload[0], payload[1]]);
        let name = match version {
            1 => "NetFlow v1",
            5 => "NetFlow v5",
            7 => "NetFlow v7",
            9 => "NetFlow v9",
            10 => "IPFIX",
            _ => "NetFlow",
        };
        format!("{name} flow export")
    } else {
        "NetFlow (truncated)".to_string()
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Netflow,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipfix() {
        let r = dissect_netflow(None, None, 40000, 4739, &[0x00, 0x0A, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Netflow);
        assert_eq!(r.summary, "IPFIX flow export");
    }

    #[test]
    fn v9() {
        let r = dissect_netflow(None, None, 40000, 2055, &[0x00, 0x09, 0x00, 0x00]);
        assert_eq!(r.summary, "NetFlow v9 flow export");
    }
}
