// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Whether an 802.3 LLC payload carries a Spanning Tree BPDU. STP frames use the
/// LLC DSAP/SSAP pair 0x42/0x42, which is the reliable signature to key on.
pub fn is_stp(llc_payload: &[u8]) -> bool {
    llc_payload.len() >= 3 && llc_payload[0] == 0x42 && llc_payload[1] == 0x42
}

/// Dissect a Spanning Tree Protocol BPDU from an 802.3 LLC payload.
///
/// STP (and its faster successors RSTP/MSTP) stops switching loops by electing a
/// root bridge and disabling redundant links. Switches exchange BPDUs
/// (Bridge Protocol Data Units) inside 802.3 LLC frames: after the 3-byte LLC
/// header comes a protocol id(2, always 0), a version (0 STP, 2 RSTP, 3 MSTP),
/// a BPDU type, and — for configuration BPDUs — the root bridge id. We name the
/// variant and BPDU type, and surface the root bridge, which is the thing loop
/// troubleshooting revolves around.
pub fn dissect_stp(llc_payload: &[u8]) -> DissectedResult {
    let base = DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Stp,
        summary: String::new(),
    };

    // Skip the 3-byte LLC header (DSAP, SSAP, control) to reach the BPDU.
    let bpdu = &llc_payload[3.min(llc_payload.len())..];
    if bpdu.len() < 4 {
        return DissectedResult {
            summary: "STP BPDU (partial)".into(),
            ..base
        };
    }

    let version = bpdu[2];
    let bpdu_type = bpdu[3];
    let variant = match version {
        0 => "STP",
        2 => "RSTP",
        3 => "MSTP",
        _ => "STP",
    };

    let summary = match bpdu_type {
        0x00 => match root_bridge(bpdu) {
            Some(root) => format!("{variant} Configuration BPDU — root {root}"),
            None => format!("{variant} Configuration BPDU"),
        },
        0x02 => match root_bridge(bpdu) {
            Some(root) => format!("{variant} BPDU — root {root}"),
            None => format!("{variant} BPDU"),
        },
        0x80 => format!("{variant} Topology Change Notification"),
        other => format!("{variant} BPDU type 0x{other:02x}"),
    };

    DissectedResult { summary, ..base }
}

/// The root bridge id in a configuration BPDU: a 2-byte priority + 6-byte MAC.
/// It follows protocol-id(2), version(1), type(1) and flags(1), so it starts at
/// offset 5 of the BPDU. Rendered priority/MAC.
fn root_bridge(bpdu: &[u8]) -> Option<String> {
    let id = bpdu.get(5..13)?;
    let priority = u16::from_be_bytes([id[0], id[1]]);
    let mac = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        id[2], id[3], id[4], id[5], id[6], id[7]
    );
    Some(format!("{priority}/{mac}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_bpdu() -> Vec<u8> {
        // LLC header 0x42 0x42 0x03, then BPDU.
        let mut p = vec![0x42, 0x42, 0x03];
        p.extend_from_slice(&[0x00, 0x00]); // protocol id
        p.push(0x00); // version = STP
        p.push(0x00); // type = config
        p.push(0x00); // flags
                      // root bridge id: priority 32768 + MAC
        p.extend_from_slice(&32768u16.to_be_bytes());
        p.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        p.extend_from_slice(&[0u8; 20]);
        p
    }

    #[test]
    fn detects_stp_llc() {
        assert!(is_stp(&[0x42, 0x42, 0x03]));
        assert!(!is_stp(&[0xaa, 0xaa, 0x03]));
    }

    #[test]
    fn config_bpdu_with_root() {
        let r = dissect_stp(&config_bpdu());
        assert_eq!(r.protocol, Protocol::Stp);
        assert_eq!(
            r.summary,
            "STP Configuration BPDU — root 32768/00:11:22:33:44:55"
        );
    }

    #[test]
    fn rstp_bpdu() {
        let mut p = vec![0x42, 0x42, 0x03, 0x00, 0x00, 0x02, 0x02, 0x00];
        p.extend_from_slice(&32768u16.to_be_bytes());
        p.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        p.extend_from_slice(&[0u8; 20]);
        let r = dissect_stp(&p);
        assert!(r
            .summary
            .starts_with("RSTP BPDU — root 32768/00:11:22:33:44:55"));
    }
}
