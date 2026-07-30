// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an Ethernet POWERLINK frame (EtherType 0x88AB) — a real-time
/// industrial protocol for motion control. Byte 0 is the message type.
pub fn dissect_powerlink(payload: &[u8]) -> DissectedResult {
    let summary = match payload.first() {
        Some(&t) => {
            let name = match t {
                0x01 => "SoC (Start of Cyclic)",
                0x03 => "PReq (Poll Request)",
                0x04 => "PRes (Poll Response)",
                0x05 => "SoA (Start of Async)",
                0x06 => "ASnd (Async Send)",
                _ => "frame",
            };
            format!("POWERLINK {name}")
        }
        None => "POWERLINK (empty)".to_string(),
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Powerlink,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poll_response() {
        let r = dissect_powerlink(&[0x04, 0x01, 0xF0, 0x00]);
        assert_eq!(r.protocol, Protocol::Powerlink);
        assert!(r.summary.contains("PRes"), "{}", r.summary);
    }
}
