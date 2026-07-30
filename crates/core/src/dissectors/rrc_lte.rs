// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an LTE RRC (Radio Resource Control — 3GPP TS 36.331) PDU.
pub fn dissect_rrc_lte(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.is_empty() {
        format!("RRC LTE ({})", super::bytes(0u64))
    } else {
        let msg_type = payload[0] & 0x0F;
        let type_desc = match msg_type {
            0 => "RRCConnectionRequest",
            1 => "RRCConnectionSetup",
            2 => "RRCConnectionSetupComplete",
            3 => "RRCConnectionReconfiguration",
            4 => "RRCConnectionReconfigurationComplete",
            5 => "RRCConnectionReestablishmentRequest",
            6 => "RRCConnectionRelease",
            7 => "SecurityModeCommand",
            8 => "SecurityModeComplete",
            _ => "RRC PDU",
        };

        format!("LTE RRC {type_desc} (Type {msg_type})")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::RrcLte,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rrc_lte_connection_request() {
        // Msg Type = 0 (RRCConnectionRequest)
        let payload = vec![0x00, 0x10];
        let res = dissect_rrc_lte(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::RrcLte);
        assert!(res.summary.contains("RRCConnectionRequest"));
    }

    #[test]
    fn test_rrc_lte_empty_payload() {
        let payload = vec![];
        let res = dissect_rrc_lte(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::RrcLte);
        assert!(res.summary.contains("RRC LTE (0 bytes)"));
    }
}
