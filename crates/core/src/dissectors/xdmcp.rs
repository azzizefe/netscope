// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an XDMCP message (UDP 177) — the X Display Manager Control
/// Protocol, which lets an X terminal ask a remote host for a login session.
/// Bytes 0..2 are the version (1), bytes 2..4 the opcode.
pub fn dissect_xdmcp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        let opcode = u16::from_be_bytes([payload[2], payload[3]]);
        let name = match opcode {
            1 => "BroadcastQuery",
            2 => "Query",
            3 => "IndirectQuery",
            4 => "ForwardQuery",
            5 => "Willing",
            6 => "Unwilling",
            7 => "Request",
            8 => "Accept",
            9 => "Manage",
            10 => "Refuse",
            11 => "Failed",
            12 => "KeepAlive",
            13 => "Alive",
            _ => "message",
        };
        format!("XDMCP {name}")
    } else {
        format!("XDMCP ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Xdmcp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query() {
        // version 1, opcode 2 (Query).
        let r = dissect_xdmcp(None, None, 40000, 177, &[0x00, 0x01, 0x00, 0x02]);
        assert_eq!(r.protocol, Protocol::Xdmcp);
        assert_eq!(r.summary, "XDMCP Query");
    }
}
