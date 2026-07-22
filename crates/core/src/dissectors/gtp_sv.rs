// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Sv Interface Message Types (3GPP TS 29.280 §6.1).
fn gtp_sv_message_name(msg_type: u8) -> &'static str {
    match msg_type {
        1 => "Echo Request",
        2 => "Echo Response",
        0x44 => "PS to CS Handover Request",
        0x45 => "PS to CS Handover Response",
        0x46 => "PS to CS Handover Cancel Request",
        0x47 => "PS to CS Handover Cancel Response",
        0x48 => "PS to CS Handover Complete Notification",
        0x49 => "PS to CS Handover Complete Acknowledge",
        _ => "GTP Sv Message",
    }
}

/// Dissect a GTP Sv (3GPP TS 29.280 SRVCC voice handover) message over UDP 2123/2152.
pub fn dissect_gtp_sv(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        format!("GTP Sv ({})", super::bytes(payload.len() as u64))
    } else {
        let msg_type = payload[1];
        let msg_name = gtp_sv_message_name(msg_type);

        format!("GTP Sv Interface {msg_name} (Type {msg_type})")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::GtpSv,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtp_sv_handover_request() {
        // Flags = 0x48, Msg Type = 0x44 (PS to CS Handover Request)
        let payload = vec![0x48, 0x44, 0x00, 0x10];
        let res = dissect_gtp_sv(None, None, 2123, 2123, &payload);
        assert_eq!(res.protocol, Protocol::GtpSv);
        assert!(res.summary.contains("PS to CS Handover Request"));
    }

    #[test]
    fn test_gtp_sv_short_payload() {
        let payload = vec![0x48, 0x01];
        let res = dissect_gtp_sv(None, None, 2123, 2123, &payload);
        assert_eq!(res.protocol, Protocol::GtpSv);
        assert!(res.summary.contains("GTP Sv (2 bytes)"));
    }
}
