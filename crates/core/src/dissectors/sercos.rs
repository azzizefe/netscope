// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a SERCOS III frame (EtherType 0x88CD) — a real-time bus for motion
/// control (servo drives). The telegram type lives in the low bits of byte 1 of
/// the SERCOS header.
pub fn dissect_sercos(payload: &[u8]) -> DissectedResult {
    let summary = match payload.get(1) {
        Some(&b) => {
            // Bit 0 distinguishes the two real-time channels (MDT vs AT).
            let telegram = if b & 0x01 == 0 { "MDT (master data)" } else { "AT (drive data)" };
            format!("SERCOS III {telegram}")
        }
        None => "SERCOS III (truncated)".to_string(),
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Sercos,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mdt_telegram() {
        let r = dissect_sercos(&[0x00, 0x00, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Sercos);
        assert!(r.summary.contains("MDT"), "{}", r.summary);
    }
}
