// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an AARP packet (EtherType 0x80F3) — AppleTalk Address Resolution
/// Protocol, the AppleTalk equivalent of ARP. Bytes 6..8 hold the function.
pub fn dissect_aarp(payload: &[u8]) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let name = match u16::from_be_bytes([payload[6], payload[7]]) {
            1 => "Request",
            2 => "Response",
            3 => "Probe",
            _ => "message",
        };
        format!("AARP {name}")
    } else {
        "AARP (truncated)".to_string()
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Aarp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe() {
        let p = [0x00, 0x01, 0x80, 0x9B, 0x06, 0x04, 0x00, 0x03];
        let r = dissect_aarp(&p);
        assert_eq!(r.protocol, Protocol::Aarp);
        assert_eq!(r.summary, "AARP Probe");
    }
}
