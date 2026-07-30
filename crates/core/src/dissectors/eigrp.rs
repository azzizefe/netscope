// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an EIGRP packet (IP protocol 88) — Cisco's interior routing
/// protocol. Byte 0 is the version, byte 1 the opcode (RFC 7868).
pub fn dissect_eigrp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    let summary = match (payload.first(), payload.get(1)) {
        (Some(&version), Some(&opcode)) => {
            let name = match opcode {
                1 => "Update",
                2 => "Request",
                3 => "Query",
                4 => "Reply",
                5 => "Hello",
                10 => "SIA-Query",
                11 => "SIA-Reply",
                _ => "message",
            };
            format!("EIGRPv{version} {name}")
        }
        _ => "EIGRP (truncated)".to_string(),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Eigrp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello() {
        let r = dissect_eigrp(None, None, &[0x02, 0x05, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Eigrp);
        assert_eq!(r.summary, "EIGRPv2 Hello");
    }
}
