// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Banyan VINES packet (EtherType 0x0BAD) — the network stack of
/// Banyan VINES, a Unix-based server platform popular in the early 90s. Byte 5
/// of the VINES IP header names the upper-layer protocol.
pub fn dissect_vines(payload: &[u8]) -> DissectedResult {
    let summary = match payload.get(5) {
        Some(&proto) => {
            let name = match proto {
                1 => "IPC",
                2 => "SPP (sequenced packet)",
                4 => "ARP",
                5 => "ICP (control)",
                6 => "RTP (routing)",
                _ => "packet",
            };
            format!("Banyan VINES — {name}")
        }
        None => "Banyan VINES (truncated)".to_string(),
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Vines,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing() {
        // checksum(2), length(2), transport control(1), protocol 6 (RTP).
        let r = dissect_vines(&[0x00, 0x00, 0x00, 0x2E, 0x0F, 0x06]);
        assert_eq!(r.protocol, Protocol::Vines);
        assert!(r.summary.contains("RTP"), "{}", r.summary);
    }
}
