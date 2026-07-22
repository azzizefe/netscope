// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect X10 home automation over IP bridge commands (TCP/UDP 10000).
pub fn dissect_x10(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 2 {
        let house_code = match (payload[0] >> 4) & 0x0F {
            0x06 => 'A',
            0x0E => 'B',
            0x02 => 'C',
            0x0A => 'D',
            0x01 => 'E',
            0x09 => 'F',
            0x05 => 'G',
            0x0D => 'H',
            _ => 'X',
        };
        let cmd = payload[1] & 0x0F;
        let cmd_name = match cmd {
            0x02 => "ON",
            0x03 => "OFF",
            0x04 => "DIM",
            0x05 => "BRIGHT",
            0x00 => "ALL UNITS OFF",
            0x01 => "ALL LIGHTS ON",
            _ => "COMMAND",
        };
        format!("X10 House {house_code} {cmd_name}")
    } else {
        format!("X10 ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::X10,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x10_on() {
        let payload = vec![0x60, 0x02];
        let r = dissect_x10(None, None, 40000, 10000, &payload);
        assert_eq!(r.protocol, Protocol::X10);
        assert_eq!(r.summary, "X10 House A ON");
    }
}
