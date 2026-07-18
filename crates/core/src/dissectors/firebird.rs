// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Firebird message (TCP 3050) — the wire protocol of the Firebird
/// relational database (and its InterBase ancestor). Each packet opens with a
/// 4-byte big-endian operation code.
pub fn dissect_firebird(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        let op = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let name = match op {
            1 => "connect",
            3 => "accept",
            4 => "reject",
            6 => "disconnect",
            9 => "response",
            19 => "attach",
            21 => "detach",
            35 => "compile (statement)",
            48 => "fetch",
            _ => "operation",
        };
        format!("Firebird {name}")
    } else {
        format!("Firebird ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Firebird,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attach() {
        let r = dissect_firebird(None, None, 40000, 3050, &19u32.to_be_bytes());
        assert_eq!(r.protocol, Protocol::Firebird);
        assert_eq!(r.summary, "Firebird attach");
    }
}
