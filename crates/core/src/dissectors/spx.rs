// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Sequenced Packet Exchange (SPX, IPX packet type 5) frame.
pub fn dissect_spx(payload: &[u8]) -> DissectedResult {
    let summary = if payload.len() >= 12 {
        let conn_ctl = payload[0];
        let datastream = payload[1];
        let flags_str = match conn_ctl {
            0x10 => "End-of-Data",
            0x20 => "Attention",
            0x40 => "Ack Required",
            0x80 => "System Packet",
            _ => "Data",
        };
        format!("IPX SPX {flags_str} (stream 0x{datastream:02X})")
    } else {
        format!("IPX SPX ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Spx,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spx_packet() {
        let payload = vec![0x40, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01];
        let r = dissect_spx(&payload);
        assert_eq!(r.protocol, Protocol::Spx);
        assert!(r.summary.contains("Ack Required"));
    }
}
