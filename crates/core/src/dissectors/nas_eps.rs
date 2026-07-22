// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// NAS-EPS Message Types (3GPP TS 24.301 §9.8 / §9.9).
fn nas_eps_message_name(msg_type: u8) -> &'static str {
    match msg_type {
        0x41 => "Attach Request",
        0x42 => "Attach Accept",
        0x43 => "Attach Complete",
        0x44 => "Attach Reject",
        0x45 => "Detach Request",
        0x46 => "Detach Accept",
        0x48 => "Tracking Area Update Request",
        0x49 => "Tracking Area Update Accept",
        0x4C => "Service Request",
        0x4E => "Extended Service Request",
        0x50 => "GUTI Reallocation Command",
        0x52 => "Authentication Request",
        0x53 => "Authentication Response",
        0x54 => "Authentication Reject",
        0x55 => "Identity Request",
        0x56 => "Identity Response",
        0x5D => "Security Mode Command",
        0x5E => "Security Mode Complete",
        0x5F => "Security Mode Reject",
        0x65 => "EMM Status",
        _ => "NAS-EPS Message",
    }
}

/// Dissect an EPS NAS (3GPP TS 24.301 LTE Non-Access Stratum) message.
pub fn dissect_nas_eps(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 3 {
        format!("NAS-EPS ({})", super::bytes(payload.len() as u64))
    } else {
        let sec_hdr = payload[0] & 0x0F;
        let _proto_disc = payload[1] & 0x0F;
        let msg_type = payload[2];

        let sec_name = match sec_hdr {
            0 => "Plain NAS",
            1 => "Integrity Protected",
            2 => "Integrity & Ciphered",
            3 => "Integrity & New Security Context",
            4 => "Integrity & Ciphered & New Security Context",
            _ => "Security Header",
        };
        let msg_name = nas_eps_message_name(msg_type);

        format!("LTE NAS-EPS {msg_name} (Type 0x{msg_type:02X}) — {sec_name}")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::NasEps,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nas_eps_attach_request() {
        // Sec Hdr = 0 (Plain), Proto Disc = 7 (EPS Mobility Management), Msg Type = 0x41 (Attach Request)
        let payload = vec![0x00, 0x07, 0x41, 0x00];
        let res = dissect_nas_eps(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::NasEps);
        assert!(res.summary.contains("Attach Request"));
        assert!(res.summary.contains("Plain NAS"));
    }

    #[test]
    fn test_nas_eps_short_payload() {
        let payload = vec![0x00, 0x01];
        let res = dissect_nas_eps(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::NasEps);
        assert!(res.summary.contains("NAS-EPS (2 bytes)"));
    }
}
