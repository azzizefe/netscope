// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a PPPoE frame. Discovery (EtherType 0x8863) negotiates a session;
/// Session (0x8864) carries the PPP payload. Byte 1 is the code, bytes 2..4
/// the session id (RFC 2516).
pub fn dissect_pppoe(payload: &[u8], session_stage: bool) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        let code = payload[1];
        let session_id = u16::from_be_bytes([payload[2], payload[3]]);
        if session_stage {
            format!("PPPoE session (id 0x{session_id:04x})")
        } else {
            let name = match code {
                0x09 => "PADI (discovery init)",
                0x07 => "PADO (offer)",
                0x19 => "PADR (request)",
                0x65 => "PADS (session confirm)",
                0xa7 => "PADT (terminate)",
                _ => "discovery",
            };
            format!("PPPoE {name}")
        }
    } else {
        "PPPoE (truncated)".to_string()
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Pppoe,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padi_discovery() {
        let r = dissect_pppoe(&[0x11, 0x09, 0x00, 0x00], false);
        assert_eq!(r.protocol, Protocol::Pppoe);
        assert!(r.summary.starts_with("PPPoE PADI"), "{}", r.summary);
    }

    #[test]
    fn session() {
        let r = dissect_pppoe(&[0x11, 0x00, 0x00, 0x2A], true);
        assert_eq!(r.summary, "PPPoE session (id 0x002a)");
    }
}
