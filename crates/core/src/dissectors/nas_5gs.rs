// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// NAS-5GS Message Types (3GPP TS 24.501 §9.7 / §9.8).
fn nas_5gs_message_name(msg_type: u8) -> &'static str {
    match msg_type {
        0x41 => "Registration Request",
        0x42 => "Registration Accept",
        0x43 => "Registration Complete",
        0x44 => "Registration Reject",
        0x45 => "Deregistration Request (UE originating)",
        0x46 => "Deregistration Accept (UE originating)",
        0x4C => "Service Request",
        0x4D => "Service Reject",
        0x4E => "Control Plane Service Request",
        0x56 => "Authentication Request",
        0x57 => "Authentication Response",
        0x58 => "Authentication Reject",
        0x5B => "Identity Request",
        0x5C => "Identity Response",
        0x5E => "Security Mode Command",
        0x5F => "Security Mode Complete",
        0x67 => "5GMM Status",
        0xC1 => "PDU Session Establishment Request",
        0xC2 => "PDU Session Establishment Accept",
        0xC3 => "PDU Session Establishment Reject",
        _ => "NAS-5GS Message",
    }
}

/// Dissect a 5GS NAS (3GPP TS 24.501 5G Non-Access Stratum) message.
pub fn dissect_nas_5gs(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 3 {
        format!("NAS-5GS ({})", super::bytes(payload.len() as u64))
    } else {
        let sec_hdr = payload[0] & 0x0F;
        let _proto_disc = payload[1] & 0x0F;
        let msg_type = payload[2];

        let sec_name = match sec_hdr {
            0 => "Plain 5GS NAS",
            1 => "Integrity Protected",
            2 => "Integrity & Ciphered",
            3 => "Integrity & New 5G Security Context",
            4 => "Integrity & Ciphered & New 5G Security Context",
            _ => "Security Header",
        };
        let msg_name = nas_5gs_message_name(msg_type);

        format!("5G NAS-5GS {msg_name} (Type 0x{msg_type:02X}) — {sec_name}")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Nas5gs,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nas_5gs_registration_request() {
        // Sec Hdr = 0 (Plain), Proto Disc = 7 (5GMM), Msg Type = 0x41 (Registration Request)
        let payload = vec![0x00, 0x7E, 0x41, 0x00];
        let res = dissect_nas_5gs(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Nas5gs);
        assert!(res.summary.contains("Registration Request"));
        assert!(res.summary.contains("Plain 5GS NAS"));
    }

    #[test]
    fn test_nas_5gs_short_payload() {
        let payload = vec![0x00, 0x01];
        let res = dissect_nas_5gs(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Nas5gs);
        assert!(res.summary.contains("NAS-5GS (2 bytes)"));
    }
}
