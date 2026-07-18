// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an AoE frame (EtherType 0x88A2) — ATA over Ethernet, which exports
/// a disk directly onto the LAN with no IP layer at all. Simple and fast, but
/// unrouted and unauthenticated. Byte 5 is the command.
pub fn dissect_aoe(payload: &[u8]) -> DissectedResult {
    let summary = if payload.len() >= 6 {
        let major = u16::from_be_bytes([payload[1], payload[2]]);
        let minor = payload[3];
        let name = match payload[5] {
            0 => "ATA command",
            1 => "Query Config",
            2 => "MAC Mask List",
            3 => "Reserve/Release",
            _ => "command",
        };
        format!("AoE {name} — shelf {major}, slot {minor}")
    } else {
        "AoE (truncated)".to_string()
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Aoe,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ata_command() {
        // ver/flags, major(2)=1, minor=0, error, command 0 (ATA).
        let r = dissect_aoe(&[0x10, 0x00, 0x01, 0x00, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Aoe);
        assert!(r.summary.contains("shelf 1, slot 0"), "{}", r.summary);
    }
}
