// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect Insteon powerline / RF smart home gateway messages (TCP/UDP 9761).
pub fn dissect_insteon(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let cmd1 = payload[6];
        let cmd_name = match cmd1 {
            0x11 => "Standard ON",
            0x12 => "Fast ON",
            0x13 => "Standard OFF",
            0x14 => "Fast OFF",
            0x19 => "Status Request",
            0x2E => "Extended Set",
            _ => "Command",
        };
        format!("Insteon {cmd_name} (Cmd1 0x{cmd1:02X})")
    } else {
        format!("Insteon ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Insteon,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insteon_on() {
        let payload = vec![0x02, 0x62, 0x12, 0x34, 0x56, 0x0F, 0x11, 0xFF];
        let r = dissect_insteon(None, None, 40000, 9761, &payload);
        assert_eq!(r.protocol, Protocol::Insteon);
        assert_eq!(r.summary, "Insteon Standard ON (Cmd1 0x11)");
    }
}
