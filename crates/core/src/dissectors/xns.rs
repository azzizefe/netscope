// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Xerox Network Systems IDP (XNS, EtherType 0x0600) frame.
pub fn dissect_xns(payload: &[u8]) -> DissectedResult {
    let summary = if payload.len() >= 5 {
        let pkt_type = payload[4];
        let name = match pkt_type {
            0 => "Routing Info",
            1 => "Echo",
            2 => "Error",
            4 => "PEP (Packet Exchange)",
            5 => "SPP (Sequenced Packet)",
            _ => "Packet",
        };
        format!("XNS IDP {name}")
    } else {
        format!("XNS IDP ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Xns,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xns_echo() {
        let payload = vec![0xFF, 0xFF, 0x00, 0x1E, 0x01];
        let r = dissect_xns(&payload);
        assert_eq!(r.protocol, Protocol::Xns);
        assert_eq!(r.summary, "XNS IDP Echo");
    }
}
