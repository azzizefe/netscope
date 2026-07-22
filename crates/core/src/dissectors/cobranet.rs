// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect CobraNet digital audio over Ethernet frame (EtherType `0x8819`).
pub fn dissect_cobranet(payload: &[u8]) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        let pkt_type = u16::from_be_bytes([payload[0], payload[1]]);
        let type_name = match pkt_type {
            0x0001 => "Beat Packet",
            0x0002 => "Audio Data",
            0x0003 => "Conductor Map",
            _ => "Packet",
        };
        let bundle = u16::from_be_bytes([payload[2], payload[3]]);
        format!("CobraNet {type_name} (Bundle {bundle})")
    } else {
        format!("CobraNet ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Cobranet,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cobranet_beat() {
        let payload = vec![0x00, 0x01, 0x00, 0x01];
        let r = dissect_cobranet(&payload);
        assert_eq!(r.protocol, Protocol::Cobranet);
        assert_eq!(r.summary, "CobraNet Beat Packet (Bundle 1)");
    }
}
