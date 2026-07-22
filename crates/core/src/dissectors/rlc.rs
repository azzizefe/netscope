// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an RLC (Radio Link Control — 3GPP TS 36.322 / TS 38.322) PDU.
pub fn dissect_rlc(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.is_empty() {
        format!("RLC ({})", super::bytes(0u64))
    } else {
        let dc_bit = (payload[0] & 0x80) >> 7;
        if dc_bit == 1 {
            // Data PDU (AM/UM)
            let poll = (payload[0] & 0x40) >> 6;
            let sn = if payload.len() >= 2 {
                u16::from_be_bytes([payload[0] & 0x0F, payload[1]])
            } else {
                (payload[0] & 0x3F) as u16
            };
            let poll_str = if poll == 1 { " (Poll)" } else { "" };
            format!("RLC Acknowledged Mode (AM) Data PDU — SN {sn}{poll_str}")
        } else {
            // Control PDU (Status PDU)
            let cptu = (payload[0] & 0x70) >> 4;
            let type_desc = match cptu {
                0 => "Status PDU",
                _ => "Control PDU",
            };
            format!("RLC {type_desc}")
        }
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Rlc,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rlc_am_data_pdu() {
        // DC bit = 1, Poll = 1 (0xC0), SN = 50
        let payload = vec![0xC0, 0x32, 0x00];
        let res = dissect_rlc(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Rlc);
        assert!(res.summary.contains("AM"));
        assert!(res.summary.contains("SN 50"));
        assert!(res.summary.contains("Poll"));
    }

    #[test]
    fn test_rlc_empty_payload() {
        let payload = vec![];
        let res = dissect_rlc(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Rlc);
        assert!(res.summary.contains("RLC (0 bytes)"));
    }
}
