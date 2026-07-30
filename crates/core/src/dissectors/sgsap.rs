// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// SGsAP Message Types (3GPP TS 29.118 §9.2).
fn sgsap_message_name(msg_type: u8) -> &'static str {
    match msg_type {
        0x01 => "SGsAP-LOCATION-UPDATE-REQUEST",
        0x02 => "SGsAP-LOCATION-UPDATE-ACCEPT",
        0x03 => "SGsAP-LOCATION-UPDATE-REJECT",
        0x07 => "SGsAP-PAGING-REQUEST",
        0x08 => "SGsAP-PAGING-REJECT",
        0x0B => "SGsAP-SERVICE-REQUEST",
        0x0E => "SGsAP-ALERT-REQUEST",
        0x0F => "SGsAP-ALERT-ACK",
        0x10 => "SGsAP-ALERT-REJECT",
        0x12 => "SGsAP-STATUS",
        0x17 => "SGsAP-EPS-DETACH-INDICATION",
        0x18 => "SGsAP-EPS-DETACH-ACK",
        0x19 => "SGsAP-IMSI-DETACH-INDICATION",
        0x1A => "SGsAP-IMSI-DETACH-ACK",
        _ => "SGsAP Message",
    }
}

/// Dissect an SGsAP (SGs Application Protocol — 3GPP TS 29.118 MME-VLR CS Fallback) message over SCTP.
pub fn dissect_sgsap(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.is_empty() {
        format!("SGsAP ({})", super::bytes(0u64))
    } else {
        let msg_type = payload[0];
        let msg_name = sgsap_message_name(msg_type);

        format!("SGsAP {msg_name} (Type 0x{msg_type:02X})")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Sgsap,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sgsap_location_update_request() {
        // Msg Type = 0x01 (SGsAP-LOCATION-UPDATE-REQUEST)
        let payload = vec![0x01, 0x00, 0x10];
        let res = dissect_sgsap(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Sgsap);
        assert!(res.summary.contains("SGsAP-LOCATION-UPDATE-REQUEST"));
    }

    #[test]
    fn test_sgsap_empty_payload() {
        let payload = vec![];
        let res = dissect_sgsap(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Sgsap);
        assert!(res.summary.contains("SGsAP (0 bytes)"));
    }
}
