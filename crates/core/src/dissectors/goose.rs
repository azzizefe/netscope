// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a GOOSE frame (EtherType 0x88B8) — IEC 61850 substation event
/// messaging. It rides directly on Ethernet for speed; the first two bytes
/// after the EtherType are the APPID.
pub fn dissect_goose(payload: &[u8]) -> DissectedResult {
    let summary = if payload.len() >= 2 {
        let appid = u16::from_be_bytes([payload[0], payload[1]]);
        format!("GOOSE — APPID 0x{appid:04x} (IEC 61850 substation event)")
    } else {
        "GOOSE (truncated)".to_string()
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Goose,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appid() {
        let r = dissect_goose(&[0x00, 0x01, 0x00, 0x10]);
        assert_eq!(r.protocol, Protocol::Goose);
        assert!(r.summary.contains("APPID 0x0001"), "{}", r.summary);
    }
}
