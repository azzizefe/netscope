// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a 5G NR RRC (Radio Resource Control — 3GPP TS 38.331) PDU.
pub fn dissect_rrc_nr(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.is_empty() {
        format!("RRC NR ({})", super::bytes(0u64))
    } else {
        let msg_type = payload[0] & 0x0F;
        let type_desc = match msg_type {
            0 => "RRCSetupRequest",
            1 => "RRCSetup",
            2 => "RRCSetupComplete",
            3 => "RRCReconfiguration",
            4 => "RRCReconfigurationComplete",
            5 => "RRCResumeRequest",
            6 => "RRCRelease",
            7 => "SecurityModeCommand",
            8 => "SecurityModeComplete",
            _ => "NR RRC PDU",
        };

        format!("5G NR RRC {type_desc} (Type {msg_type})")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::RrcNr,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rrc_nr_setup_request() {
        // Msg Type = 0 (RRCSetupRequest)
        let payload = vec![0x00, 0x10];
        let res = dissect_rrc_nr(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::RrcNr);
        assert!(res.summary.contains("RRCSetupRequest"));
    }

    #[test]
    fn test_rrc_nr_empty_payload() {
        let payload = vec![];
        let res = dissect_rrc_nr(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::RrcNr);
        assert!(res.summary.contains("RRC NR (0 bytes)"));
    }
}
