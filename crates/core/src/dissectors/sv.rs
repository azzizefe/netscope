// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Sampled Values frame (EtherType 0x88BA) — IEC 61850-9-2 streams of
/// digitised current/voltage measurements from substation sensors. Rides
/// directly on Ethernet; bytes 0..2 are the APPID.
pub fn dissect_sv(payload: &[u8]) -> DissectedResult {
    let summary = if payload.len() >= 2 {
        let appid = u16::from_be_bytes([payload[0], payload[1]]);
        format!("Sampled Values — APPID 0x{appid:04x} (IEC 61850-9-2)")
    } else {
        "Sampled Values (truncated)".to_string()
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Sv,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appid() {
        let r = dissect_sv(&[0x40, 0x00, 0x00, 0x20]);
        assert_eq!(r.protocol, Protocol::Sv);
        assert!(r.summary.contains("APPID 0x4000"), "{}", r.summary);
    }
}
