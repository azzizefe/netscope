// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a GVCP message (UDP 3956) — GigE Vision Control Protocol, how
/// industrial/machine-vision cameras are discovered and configured. A command
/// starts with the 0x42 key; bytes 2..4 hold the command code.
pub fn dissect_gvcp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.first() == Some(&0x42) && payload.len() >= 4 {
        let cmd = u16::from_be_bytes([payload[2], payload[3]]);
        let name = match cmd {
            0x0002 => "Discovery",
            0x0004 => "ForceIP",
            0x0040 => "Packet-Resend",
            0x0080 => "ReadReg",
            0x0082 => "WriteReg",
            0x0084 => "ReadMem",
            0x0086 => "WriteMem",
            _ => "command",
        };
        format!("GVCP {name}")
    } else {
        "GVCP acknowledge".to_string()
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Gvcp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery() {
        let r = dissect_gvcp(None, None, 40000, 3956, &[0x42, 0x01, 0x00, 0x02]);
        assert_eq!(r.protocol, Protocol::Gvcp);
        assert_eq!(r.summary, "GVCP Discovery");
    }
}
