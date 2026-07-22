// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an AUTOSAR I-PDU / Container PDU / PDU Router frame.
/// Carries structured signals and multiplexed IPDUs across CAN/SOME-IP/Ethernet.
pub fn dissect_autosar_pdu(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        format!("AUTOSAR PDU ({})", super::bytes(payload.len() as u64))
    } else {
        let pdu_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let pdu_len = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);

        format!("AUTOSAR Container I-PDU ID 0x{pdu_id:08X} — length {pdu_len} bytes")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::AutosarPdu,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_autosar_pdu_container() {
        // PDU ID = 0x00001001, PDU Length = 64
        let payload = vec![0x00, 0x00, 0x10, 0x01, 0x00, 0x00, 0x00, 0x40, 0xAA, 0xBB];
        let res = dissect_autosar_pdu(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::AutosarPdu);
        assert!(res.summary.contains("PDU ID 0x00001001"));
        assert!(res.summary.contains("length 64 bytes"));
    }

    #[test]
    fn test_autosar_pdu_short_payload() {
        let payload = vec![0x01, 0x02];
        let res = dissect_autosar_pdu(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::AutosarPdu);
        assert!(res.summary.contains("AUTOSAR PDU (2 bytes)"));
    }
}
