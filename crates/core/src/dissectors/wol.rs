// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Structural check for a Wake-on-LAN magic packet: six 0xFF bytes followed by
/// the target MAC repeated 16 times. Works whether it arrives as EtherType
/// 0x0842 or inside a UDP datagram.
pub fn looks_like_wol(p: &[u8]) -> bool {
    if p.len() < 102 || p[..6] != [0xFF; 6] {
        return false;
    }
    let mac = &p[6..12];
    (0..16).all(|i| &p[6 + i * 6..12 + i * 6] == mac)
}

/// Dissect a Wake-on-LAN magic packet — the broadcast that powers a sleeping
/// machine on. The target MAC is carried 16 times over.
pub fn dissect_wol(payload: &[u8]) -> DissectedResult {
    let summary = if payload.len() >= 12 {
        let m = &payload[6..12];
        format!(
            "Wake-on-LAN — magic packet for {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        )
    } else {
        "Wake-on-LAN (truncated)".to_string()
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Wol,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_packet() {
        let mac = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01];
        let mut p = vec![0xFF; 6];
        for _ in 0..16 {
            p.extend_from_slice(&mac);
        }
        assert!(looks_like_wol(&p));
        let r = dissect_wol(&p);
        assert_eq!(r.protocol, Protocol::Wol);
        assert!(r.summary.contains("de:ad:be:ef:00:01"), "{}", r.summary);
    }
}
