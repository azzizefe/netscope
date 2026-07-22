// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Service Data Type (SDT) descriptions for CAN XL (CiA 610-1 / CiA 611-1).
fn sdt_name(sdt: u8) -> &'static str {
    match sdt {
        0x01 => "IEEE 802.3 Ethernet",
        0x02 => "IP Packets",
        0x03 => "Classic CAN / CAN FD Frame",
        0x04 => "CiA 611-1 Management",
        0x05 => "UDS (ISO 14229)",
        0x06 => "DoIP Bridge",
        _ => "Custom/Reserved SDT",
    }
}

/// Dissect a CAN XL frame (CiA 610-1 eXtra Long CAN specification).
pub fn dissect_can_xl(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 6 {
        format!("CAN XL ({})", super::bytes(payload.len() as u64))
    } else {
        let prio_id = u16::from_be_bytes([payload[0] & 0x07, payload[1]]);
        let vcid = payload[2];
        let sdt = payload[3];
        let dlc = u16::from_be_bytes([payload[4], payload[5]]) & 0x07FF;
        let sdt_desc = sdt_name(sdt);

        format!(
            "CAN XL Priority ID 0x{prio_id:03X}, VCID {vcid}, SDT 0x{sdt:02X} ({sdt_desc}) — {dlc} payload bytes"
        )
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::CanXl,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_can_xl_ethernet_sdt() {
        // PrioID = 0x100, VCID = 1, SDT = 0x01 (Ethernet), DLC = 512 bytes
        let payload = vec![0x01, 0x00, 0x01, 0x01, 0x02, 0x00];
        let res = dissect_can_xl(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::CanXl);
        assert!(res.summary.contains("Priority ID 0x100"));
        assert!(res.summary.contains("VCID 1"));
        assert!(res.summary.contains("IEEE 802.3 Ethernet"));
        assert!(res.summary.contains("512 payload bytes"));
    }

    #[test]
    fn test_can_xl_short_payload() {
        let payload = vec![0x01, 0x02];
        let res = dissect_can_xl(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::CanXl);
        assert!(res.summary.contains("CAN XL (2 bytes)"));
    }
}
