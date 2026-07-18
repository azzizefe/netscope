// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Name the PTP message from the low nibble of byte 0 (IEEE 1588).
fn message_name(payload: &[u8]) -> &'static str {
    match payload.first().map(|b| b & 0x0F) {
        Some(0x0) => "Sync",
        Some(0x1) => "Delay_Req",
        Some(0x2) => "Pdelay_Req",
        Some(0x3) => "Pdelay_Resp",
        Some(0x8) => "Follow_Up",
        Some(0x9) => "Delay_Resp",
        Some(0xA) => "Pdelay_Resp_Follow_Up",
        Some(0xB) => "Announce",
        Some(0xC) => "Signaling",
        Some(0xD) => "Management",
        _ => "message",
    }
}

/// Dissect a PTP frame carried directly on Ethernet (EtherType 0x88F7).
pub fn dissect_ptp_l2(payload: &[u8]) -> DissectedResult {
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Ptp,
        summary: format!("PTP {} (IEEE 1588 time sync)", message_name(payload)),
    }
}

/// Dissect a PTP message carried over UDP (ports 319 event / 320 general).
pub fn dissect_ptp_udp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ptp,
        summary: format!("PTP {} (IEEE 1588 time sync)", message_name(payload)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_over_ethernet() {
        let r = dissect_ptp_l2(&[0x00, 0x02, 0x00, 0x2c]);
        assert_eq!(r.protocol, Protocol::Ptp);
        assert!(r.summary.starts_with("PTP Sync"), "{}", r.summary);
    }

    #[test]
    fn announce_over_udp() {
        let r = dissect_ptp_udp(None, None, 320, 320, &[0x0B, 0x02]);
        assert!(r.summary.starts_with("PTP Announce"), "{}", r.summary);
    }
}
