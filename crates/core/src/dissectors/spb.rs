// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Shortest Path Bridging (SPB, IEEE 802.1aq, EtherType 0x88E5 or IS-IS SPB) frame.
pub fn dissect_spb(payload: &[u8]) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        let b_vid = ((payload[0] as u16 & 0x0F) << 8) | payload[1] as u16;
        format!("Shortest Path Bridging (IEEE 802.1aq) B-VID {b_vid}")
    } else {
        format!("Shortest Path Bridging ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Spb,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spb_frame() {
        let payload = vec![0x00, 0x64, 0x88, 0xE5];
        let r = dissect_spb(&payload);
        assert_eq!(r.protocol, Protocol::Spb);
        assert_eq!(r.summary, "Shortest Path Bridging (IEEE 802.1aq) B-VID 100");
    }
}
