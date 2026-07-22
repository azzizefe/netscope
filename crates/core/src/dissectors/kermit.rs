// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Check if payload looks like a Kermit packet (SOH 0x01 + ASCII length + ASCII seq + packet type).
pub(crate) fn looks_like_kermit(payload: &[u8]) -> bool {
    if payload.len() < 4 || payload[0] != 0x01 {
        return false;
    }
    if !(32..=126).contains(&payload[1]) || !(32..=126).contains(&payload[2]) {
        return false;
    }
    matches!(payload[3], b'S' | b'Y' | b'N' | b'F' | b'D' | b'Z' | b'B' | b'E' | b'G' | b'C' | b'A' | b'Q')
}

/// Dissect a Kermit File Transfer Protocol frame.
pub fn dissect_kermit(payload: &[u8]) -> DissectedResult {
    let summary = if payload.len() >= 4 && payload[0] == 0x01 {
        let pkt_type = payload[3] as char;
        let type_name = match pkt_type {
            'S' => "Send-Init",
            'Y' => "ACK",
            'N' => "NAK",
            'F' => "File Header",
            'D' => "Data",
            'Z' => "EOF",
            'B' => "EOT (Break)",
            'E' => "Error",
            'G' => "Generic Command",
            'C' => "Host Command",
            _ => "Packet",
        };
        format!("Kermit {type_name} ('{pkt_type}')")
    } else {
        format!("Kermit ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Kermit,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kermit_send_init() {
        let payload = b"\x01# S~";
        assert!(looks_like_kermit(payload));
        let r = dissect_kermit(payload);
        assert_eq!(r.protocol, Protocol::Kermit);
        assert_eq!(r.summary, "Kermit Send-Init ('S')");
    }
}
