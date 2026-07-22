// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an FCoE frame (EtherType 0x8906) — Fibre Channel storage traffic
/// carried over Ethernet in converged data-centre networks. The encapsulated
/// FC frame's R_CTL byte (after the 14-byte FCoE header) names the frame class.
pub fn dissect_fcoe(payload: &[u8]) -> DissectedResult {
    if payload.len() >= 14 {
        let inner = super::fc2::dissect_fc2(&payload[14..]);
        return DissectedResult {
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
            protocol: Protocol::Fcoe,
            summary: format!("FCoE · {}", inner.summary),
        };
    }
    let summary = match payload.get(14) {
        Some(&r_ctl) => {
            let class = match r_ctl >> 4 {
                0x0 => "device data",
                0x2 => "extended link services",
                0x3 => "FC-4 link data",
                0x8 => "basic link services",
                0xC => "link control",
                _ => "frame",
            };
            format!("FCoE — Fibre Channel {class}")
        }
        None => "FCoE frame".to_string(),
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Fcoe,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_data() {
        let mut p = vec![0u8; 14];
        p.push(0x00); // R_CTL: device data
        let r = dissect_fcoe(&p);
        assert_eq!(r.protocol, Protocol::Fcoe);
        assert!(r.summary.contains("device data"), "{}", r.summary);
    }
}
