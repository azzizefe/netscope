// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect DALI over IP (Digital Addressable Lighting Interface over IP / Ethernet, UDP 51820/4803).
pub fn dissect_dali(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 2 {
        let addr = payload[0];
        let cmd = payload[1];
        let cmd_name = match cmd {
            0x00 => "OFF",
            0x05 => "RECALL MAX",
            0x06 => "RECALL MIN",
            0x07 => "STEP DOWN",
            0x08 => "STEP UP",
            _ => "DALI Command",
        };
        let addr_type = if addr & 0x80 == 0 {
            format!("Short {}", (addr >> 1) & 0x3F)
        } else if addr == 0xFF || addr == 0xFE {
            "Broadcast".into()
        } else {
            format!("Group {}", (addr >> 1) & 0x0F)
        };
        format!("DALI over IP {addr_type} {cmd_name} (0x{cmd:02X})")
    } else {
        format!("DALI over IP ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Dali,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dali_off() {
        let payload = vec![0xFE, 0x00];
        let r = dissect_dali(None, None, 40000, 51820, &payload);
        assert_eq!(r.protocol, Protocol::Dali);
        assert_eq!(r.summary, "DALI over IP Broadcast OFF (0x00)");
    }
}
