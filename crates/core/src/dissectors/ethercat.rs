// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Name the EtherCAT datagram command (the byte after the 2-byte header).
fn command_name(cmd: u8) -> &'static str {
    match cmd {
        0 => "NOP",
        1 => "APRD (auto-inc read)",
        2 => "APWR (auto-inc write)",
        4 => "FPRD (configured read)",
        5 => "FPWR (configured write)",
        7 => "BRD (broadcast read)",
        8 => "BWR (broadcast write)",
        10 => "LRD (logical read)",
        11 => "LWR (logical write)",
        12 => "LRW (logical read/write)",
        _ => "command",
    }
}

/// Dissect an EtherCAT frame (EtherType 0x88A4) — a real-time industrial
/// fieldbus that passes a frame down a chain of slaves. The 2-byte header is
/// followed by datagrams, each starting with a command byte.
pub fn dissect_ethercat(payload: &[u8]) -> DissectedResult {
    let summary = match payload.get(2) {
        Some(&cmd) => format!("EtherCAT {}", command_name(cmd)),
        None => "EtherCAT (truncated)".to_string(),
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Ethercat,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logical_rw() {
        // 2-byte header, then command 12 (LRW).
        let r = dissect_ethercat(&[0x10, 0x10, 12, 0x00]);
        assert_eq!(r.protocol, Protocol::Ethercat);
        assert!(r.summary.contains("LRW"), "{}", r.summary);
    }
}
