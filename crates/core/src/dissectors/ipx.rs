// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an IPX packet (EtherType 0x8137) — Novell NetWare's network layer,
/// once ubiquitous on office LANs. Byte 5 is the packet type (RIP, SAP, SPX,
/// NCP…); the checksum field is conventionally 0xFFFF.
pub fn dissect_ipx(payload: &[u8]) -> DissectedResult {
    if payload.len() >= 30 {
        let pkt_type = payload[5];
        let dst_sock = u16::from_be_bytes([payload[16], payload[17]]);
        let src_sock = u16::from_be_bytes([payload[28], payload[29]]);
        if pkt_type == 5 {
            return DissectedResult {
                src_addr: None, dst_addr: None,
                src_port: Some(src_sock), dst_port: Some(dst_sock),
                protocol: Protocol::Spx,
                summary: "IPX · SPX segment".into(),
            };
        }
        if pkt_type == 17 || dst_sock == 0x0451 || src_sock == 0x0451 {
            return DissectedResult {
                src_addr: None, dst_addr: None,
                src_port: Some(src_sock), dst_port: Some(dst_sock),
                protocol: Protocol::Ncp,
                summary: "IPX · NCP request".into(),
            };
        }
    }
    let summary = if payload.len() >= 6 {
        let name = match payload[5] {
            1 => "RIP (routing)",
            4 => "SAP (service advertisement)",
            5 => "SPX",
            17 => "NCP (NetWare Core)",
            20 => "NetBIOS broadcast",
            _ => "packet",
        };
        format!("IPX {name}")
    } else {
        "IPX (truncated)".to_string()
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Ipx,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sap_packet() {
        // checksum FFFF, length, transport control, packet type 4 (SAP).
        let r = dissect_ipx(&[0xFF, 0xFF, 0x00, 0x30, 0x00, 0x04]);
        assert_eq!(r.protocol, Protocol::Ipx);
        assert!(r.summary.contains("SAP"), "{}", r.summary);
    }
}
