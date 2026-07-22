// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an NVGRE (Network Virtualization using GRE — RFC 7637 / IP Proto 47) packet.
pub fn dissect_nvgre(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        format!("NVGRE ({})", super::bytes(payload.len() as u64))
    } else {
        let vsid = u32::from_be_bytes([0, payload[4], payload[5], payload[6]]);
        let flow_id = payload[7];

        format!("NVGRE Tunnel — VSID 0x{vsid:06X} (Flow ID {flow_id})")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Nvgre,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nvgre_vsid() {
        // GRE flags = 0x2000, Proto = 0x6558, VSID = 0x001234, Flow ID = 5
        let payload = vec![0x20, 0x00, 0x65, 0x58, 0x00, 0x12, 0x34, 0x05];
        let res = dissect_nvgre(None, None, &payload);
        assert_eq!(res.protocol, Protocol::Nvgre);
        assert!(res.summary.contains("VSID 0x001234"));
        assert!(res.summary.contains("Flow ID 5"));
    }

    #[test]
    fn test_nvgre_short_payload() {
        let payload = vec![0x20, 0x00];
        let res = dissect_nvgre(None, None, &payload);
        assert_eq!(res.protocol, Protocol::Nvgre);
        assert!(res.summary.contains("NVGRE (2 bytes)"));
    }
}
