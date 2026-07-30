// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a PDCP (Packet Data Convergence Protocol — 3GPP TS 36.323 / TS 38.323) PDU.
pub fn dissect_pdcp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.is_empty() {
        format!("PDCP ({})", super::bytes(0u64))
    } else {
        let dc_bit = (payload[0] & 0x80) >> 7;
        if dc_bit == 1 {
            // Data PDU
            let sn = if payload.len() >= 2 {
                u16::from_be_bytes([payload[0] & 0x0F, payload[1]])
            } else {
                (payload[0] & 0x7F) as u16
            };
            format!("PDCP Data PDU — SN {sn}")
        } else {
            // Control PDU
            let pdu_type = (payload[0] & 0x70) >> 4;
            let type_desc = match pdu_type {
                0 => "Status Report",
                1 => "ROHC Feedback",
                _ => "Control PDU",
            };
            format!("PDCP {type_desc}")
        }
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Pdcp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pdcp_data_pdu() {
        // DC bit = 1 (Data PDU), SN = 100
        let payload = vec![0x80, 0x64, 0x00];
        let res = dissect_pdcp(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Pdcp);
        assert!(res.summary.contains("Data PDU"));
        assert!(res.summary.contains("SN 100"));
    }

    #[test]
    fn test_pdcp_empty_payload() {
        let payload = vec![];
        let res = dissect_pdcp(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Pdcp);
        assert!(res.summary.contains("PDCP (0 bytes)"));
    }
}
