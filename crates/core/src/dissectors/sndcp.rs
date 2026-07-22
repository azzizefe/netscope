// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an SNDCP (Subnetwork Dependent Convergence Protocol — 3GPP TS 44.065) packet.
pub fn dissect_sndcp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.is_empty() {
        format!("SNDCP ({})", super::bytes(0u64))
    } else {
        let nsapi = payload[0] & 0x0F;
        let first_seg = (payload[0] & 0x40) != 0;
        let pdu_type = if (payload[0] & 0x80) != 0 {
            "SN-UNITDATA PDU"
        } else {
            "SN-DATA PDU"
        };
        let seg_str = if first_seg { "First Segment" } else { "Segment" };

        format!("SNDCP {pdu_type} — NSAPI {nsapi} ({seg_str})")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Sndcp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sndcp_unitdata_first_segment() {
        // NSAPI = 5, First Segment = 1, SN-UNITDATA PDU (0x80 | 0x40 | 0x05 = 0xC5)
        let payload = vec![0xC5, 0x00, 0x01];
        let res = dissect_sndcp(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Sndcp);
        assert!(res.summary.contains("SN-UNITDATA PDU"));
        assert!(res.summary.contains("NSAPI 5"));
        assert!(res.summary.contains("First Segment"));
    }

    #[test]
    fn test_sndcp_empty_payload() {
        let payload = vec![];
        let res = dissect_sndcp(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Sndcp);
        assert!(res.summary.contains("SNDCP (0 bytes)"));
    }
}
