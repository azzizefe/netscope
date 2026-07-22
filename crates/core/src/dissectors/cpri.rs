// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a CPRI (Common Public Radio Interface) fronthaul frame.
pub fn dissect_cpri(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        format!("CPRI ({})", super::bytes(payload.len() as u64))
    } else {
        let control_byte = payload[0];
        let sub_channel = payload[1];
        let cm_type = match control_byte & 0x0F {
            0 => "C&M High Level Data Link Control (HDLC)",
            1 => "C&M Ethernet",
            2 => "L1 Inband Signaling",
            3 => "Vendor Specific C&M",
            _ => "IQ Data",
        };

        format!("CPRI Fronthaul Frame — {cm_type}, Sub-channel {sub_channel}")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Cpri,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpri_inband_signaling() {
        // Control byte = 2 (L1 Inband Signaling), Sub-channel = 1
        let payload = vec![0x02, 0x01, 0x00, 0x00];
        let res = dissect_cpri(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Cpri);
        assert!(res.summary.contains("L1 Inband Signaling"));
        assert!(res.summary.contains("Sub-channel 1"));
    }

    #[test]
    fn test_cpri_short_payload() {
        let payload = vec![0x01, 0x02];
        let res = dissect_cpri(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Cpri);
        assert!(res.summary.contains("CPRI (2 bytes)"));
    }
}
