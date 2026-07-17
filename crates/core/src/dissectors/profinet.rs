// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a PROFINET frame (EtherType 0x8892) — real-time industrial
/// automation (PLCs, IO devices). The first two bytes are the FrameID, whose
/// range selects the service (PROFINET IO / IEC 61158).
pub fn dissect_profinet(payload: &[u8]) -> DissectedResult {
    let summary = if payload.len() >= 2 {
        let frame_id = u16::from_be_bytes([payload[0], payload[1]]);
        let name = match frame_id {
            0xFEFE => "DCP Get/Set",
            0xFEFD => "DCP Hello",
            0xFEFC => "DCP Identify",
            0xFC01 => "Alarm (high priority)",
            0xFE01 => "Alarm (low priority)",
            f if (0x8000..=0xBBFF).contains(&f) => "RT Class 1 (cyclic data)",
            f if (0xFF00..=0xFF43).contains(&f) => "RT Class 3 (isochronous)",
            _ => "frame",
        };
        format!("PROFINET {name}")
    } else {
        "PROFINET (truncated)".to_string()
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Profinet,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dcp_identify() {
        let r = dissect_profinet(&[0xFE, 0xFC, 0x05, 0x00]);
        assert_eq!(r.protocol, Protocol::Profinet);
        assert_eq!(r.summary, "PROFINET DCP Identify");
    }

    #[test]
    fn cyclic_rt() {
        let r = dissect_profinet(&[0x80, 0x00, 0x00, 0x00]);
        assert!(r.summary.contains("RT Class 1"), "{}", r.summary);
    }
}
