// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a native Fibre Channel FC-2 frame (24-byte header: R_CTL, D_ID, S_ID, TYPE, F_CTL, SEQ_ID, OX_ID/RX_ID).
pub fn dissect_fc2(payload: &[u8]) -> DissectedResult {
    if payload.len() < 24 {
        return DissectedResult {
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
            protocol: Protocol::Fc2,
            summary: format!("Fibre Channel (FC-2) ({})", super::bytes(payload.len() as u64)),
        };
    }

    let r_ctl = payload[0];
    let d_id = ((payload[1] as u32) << 16) | ((payload[2] as u32) << 8) | (payload[3] as u32);
    let s_id = ((payload[5] as u32) << 16) | ((payload[6] as u32) << 8) | (payload[7] as u32);
    let fc_type = payload[8];

    // If TYPE is FCP (0x08), delegate to FCP dissector
    if fc_type == 0x08 && payload.len() > 24 {
        let fcp_res = super::fcp::dissect_fcp(&payload[24..]);
        return DissectedResult {
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
            protocol: fcp_res.protocol,
            summary: format!("FC-2 [0x{s_id:06X} -> 0x{d_id:06X}] · {}", fcp_res.summary),
        };
    }

    let class_str = match r_ctl >> 4 {
        0x0 => "device data",
        0x2 => "extended link services",
        0x3 => "FC-4 link data",
        0x8 => "basic link services",
        0xC => "link control",
        _ => "frame",
    };

    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Fc2,
        summary: format!("Fibre Channel (FC-2) {class_str} 0x{s_id:06X} -> 0x{d_id:06X}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fc2_frame() {
        let mut p = vec![0u8; 24];
        p[0] = 0x00; // device data
        p[1] = 0x00; p[2] = 0x00; p[3] = 0x01; // D_ID
        p[5] = 0x00; p[6] = 0x00; p[7] = 0x02; // S_ID
        p[8] = 0x00; // Basic FC
        let r = dissect_fc2(&p);
        assert_eq!(r.protocol, Protocol::Fc2);
        assert!(r.summary.contains("0x000002 -> 0x000001"));
    }

    #[test]
    fn test_fc2_truncated() {
        let r = dissect_fc2(&[0x00, 0x01]);
        assert_eq!(r.protocol, Protocol::Fc2);
        assert!(r.summary.contains("2 bytes"));
    }
}
