// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a DCE/RPC (MSRPC) message (TCP 135 and dynamic ports) — the Windows
/// remote-procedure-call layer behind the endpoint mapper, WMI and much of AD.
/// Byte 0 is the major version (5); byte 2 is the packet type.
pub fn dissect_dcerpc(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.first() == Some(&5) && payload.len() >= 3 {
        let name = match payload[2] {
            0 => "Request",
            2 => "Response",
            3 => "Fault",
            11 => "Bind",
            12 => "Bind Ack",
            13 => "Bind Nak",
            14 => "Alter Context",
            15 => "Alter Context Response",
            16 => "Auth3",
            _ => "PDU",
        };
        format!("DCE/RPC {name}")
    } else {
        format!("DCE/RPC ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Dcerpc,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind() {
        // version 5.0, packet type 11 (Bind).
        let r = dissect_dcerpc(None, None, 40000, 135, &[0x05, 0x00, 0x0B, 0x03]);
        assert_eq!(r.protocol, Protocol::Dcerpc);
        assert_eq!(r.summary, "DCE/RPC Bind");
    }
}
