// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a GTPv1-U (GPRS Tunnelling Protocol User Plane — 3GPP TS 29.281) packet (UDP 2152).
pub fn dissect_gtpv1u(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        format!("GTPv1-U ({})", super::bytes(payload.len() as u64))
    } else {
        let msg_type = payload[1];
        let length = u16::from_be_bytes([payload[2], payload[3]]);
        let teid = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);

        let type_desc = match msg_type {
            1 => "Echo Request",
            2 => "Echo Response",
            254 => "End Marker",
            255 => "G-PDU (User Data)",
            _ => "GTPv1-U Message",
        };

        format!("GTPv1-U {type_desc} — TEID 0x{teid:08X}, len {length}B")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Gtpv1U,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtpv1u_g_pdu() {
        // Flags = 0x30, Msg Type = 255 (G-PDU), Length = 100, TEID = 0x00001234
        let payload = vec![0x30, 0xFF, 0x00, 0x64, 0x00, 0x00, 0x12, 0x34];
        let res = dissect_gtpv1u(None, None, 2152, 2152, &payload);
        assert_eq!(res.protocol, Protocol::Gtpv1U);
        assert!(res.summary.contains("G-PDU (User Data)"));
        assert!(res.summary.contains("TEID 0x00001234"));
        assert!(res.summary.contains("len 100B"));
    }

    #[test]
    fn test_gtpv1u_short_payload() {
        let payload = vec![0x30, 0xFF];
        let res = dissect_gtpv1u(None, None, 2152, 2152, &payload);
        assert_eq!(res.protocol, Protocol::Gtpv1U);
        assert!(res.summary.contains("GTPv1-U (2 bytes)"));
    }
}
