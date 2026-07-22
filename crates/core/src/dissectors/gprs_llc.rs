// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// GPRS LLC SAPI (Service Access Point Identifier) names (3GPP TS 44.064 §6.2.3).
fn gprs_llc_sapi_name(sapi: u8) -> &'static str {
    match sapi {
        1 => "GMM (GPRS Mobility Management)",
        2 => "BSSGP",
        3 => "TOM (Tunneling Operation Mode)",
        5 => "SMS",
        7 => "SNDCP User Data (SAPI 7)",
        9 => "SNDCP User Data (SAPI 9)",
        11 => "SNDCP User Data (SAPI 11)",
        _ => "Custom SAPI",
    }
}

/// Dissect a GPRS-LLC (Logical Link Control — 3GPP TS 44.064) frame over Gb interface.
pub fn dissect_gprs_llc(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 2 {
        format!("GPRS-LLC ({})", super::bytes(payload.len() as u64))
    } else {
        let sapi = payload[0] & 0x0F;
        let control = payload[1];

        let frame_format = match (control & 0xC0) >> 6 {
            0 | 1 => "I-Frame (Information)",
            2 => "S-Frame (Supervisory)",
            3 => "U-Frame (Unnumbered)",
            _ => "LLC Frame",
        };
        let sapi_desc = gprs_llc_sapi_name(sapi);

        format!("GPRS-LLC SAPI {sapi} ({sapi_desc}) — {frame_format}")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::GprsLlc,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gprs_llc_gmm_frame() {
        // SAPI = 1 (GMM), Control = 0xC0 (U-Frame)
        let payload = vec![0x01, 0xC0, 0x00];
        let res = dissect_gprs_llc(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::GprsLlc);
        assert!(res.summary.contains("GMM"));
        assert!(res.summary.contains("U-Frame"));
    }

    #[test]
    fn test_gprs_llc_short_payload() {
        let payload = vec![0x01];
        let res = dissect_gprs_llc(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::GprsLlc);
        assert!(res.summary.contains("GPRS-LLC (1 byte)"));
    }
}
