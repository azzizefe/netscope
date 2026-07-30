// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a DECnet Phase IV packet (EtherType 0x6003) — Digital Equipment
/// Corporation's networking stack, once standard on VAX/VMS clusters. The
/// routing flags byte says whether the frame carries data or routing control.
pub fn dissect_decnet(payload: &[u8]) -> DissectedResult {
    // Ethernet-encapsulated DECnet prefixes a 2-byte length before the flags.
    let summary = match payload.get(2) {
        Some(&flags) => {
            let name = if flags & 0x01 == 0 {
                // Data packets: bits 1..3 select the message subtype.
                match (flags >> 1) & 0x07 {
                    0 => "data",
                    3 => "long data",
                    _ => "data (short)",
                }
            } else {
                match flags {
                    0x05 => "routing initialisation",
                    0x07 => "level 1 routing",
                    0x09 => "level 2 routing",
                    0x0B => "router hello",
                    0x0D => "endnode hello",
                    _ => "control",
                }
            };
            format!("DECnet Phase IV — {name}")
        }
        None => "DECnet Phase IV (truncated)".to_string(),
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Decnet,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endnode_hello() {
        let r = dissect_decnet(&[0x10, 0x00, 0x0D, 0x00]);
        assert_eq!(r.protocol, Protocol::Decnet);
        assert!(r.summary.contains("endnode hello"), "{}", r.summary);
    }
}
