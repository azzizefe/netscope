// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an AUTOSAR SecOC (Secure On-Board Communication / ISO 23132) PDU.
/// SecOC protects CAN/FlexRay/Ethernet IPDU traffic by appending a Freshness Value
/// (FV) counter and a Message Authentication Code (MAC / AES-CMAC).
pub fn dissect_secoc(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        format!("AUTOSAR SecOC ({})", super::bytes(payload.len() as u64))
    } else {
        // SecOC frame structure: Payload (N-4 bytes), Freshness Counter (1 byte), MAC (3 bytes)
        let mac_len = 3.min(payload.len().saturating_sub(1));
        let authentic_payload_len = payload.len().saturating_sub(mac_len + 1);
        let fv = payload[authentic_payload_len];
        let mac_bytes = &payload[authentic_payload_len + 1..];

        let mac_hex: Vec<String> = mac_bytes.iter().map(|b| format!("{b:02X}")).collect();
        format!(
            "AUTOSAR SecOC Secured I-PDU — payload {authentic_payload_len}B, FV counter {fv}, MAC 0x{}",
            mac_hex.join("")
        )
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::AutosarSecOc,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secoc_secured_pdu() {
        // Payload = 4 bytes [0x11, 0x22, 0x33, 0x44], FV = 0x0A (10), MAC = [0xAB, 0xCD, 0xEF]
        let payload = vec![0x11, 0x22, 0x33, 0x44, 0x0A, 0xAB, 0xCD, 0xEF];
        let res = dissect_secoc(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::AutosarSecOc);
        assert!(res.summary.contains("Secured I-PDU"));
        assert!(res.summary.contains("FV counter 10"));
        assert!(res.summary.contains("MAC 0xABCDEF"));
    }

    #[test]
    fn test_secoc_short_payload() {
        let payload = vec![0x01, 0x02];
        let res = dissect_secoc(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::AutosarSecOc);
        assert!(res.summary.contains("AUTOSAR SecOC (2 bytes)"));
    }
}
