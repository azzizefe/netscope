// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an IEEE 802.3 "Slow Protocols" frame (EtherType 0x8809).
///
/// This EtherType is shared by a small family of link-maintenance protocols. The
/// first payload byte is the subtype: LACP (1) negotiates link aggregation —
/// bundling several physical links into one logical one — its Marker companion
/// (2) drains a link before removing it, and Ethernet OAM (3) monitors link
/// health. We name the subtype (and LACP's version), which is what topology and
/// bonding checks care about.
pub fn dissect_slow(payload: &[u8]) -> DissectedResult {
    let base = DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Lacp,
        summary: String::new(),
    };

    let summary = match payload.first() {
        Some(1) => {
            let version = payload.get(1).copied().unwrap_or(1);
            format!("LACP v{version} — link aggregation")
        }
        Some(2) => "LACP Marker".to_string(),
        // Subtype 3 is link OAM, whose flags carry the two things worth
        // stopping on: a dying gasp and a degrading link.
        Some(3) => return super::link_oam::result(payload),
        // The organisation-specific subtype is shared. ESMC claims it only when
        // the ITU's identifier is present; anything else keeps the generic name
        // rather than being read as a clock quality.
        Some(10) if super::esmc::is_esmc(payload) => return super::esmc::result(payload),
        Some(10) => "Organisation-Specific Slow Protocol".to_string(),
        Some(other) => format!("Slow Protocol subtype {other}"),
        None => "Slow Protocol (empty)".to_string(),
    };

    DissectedResult { summary, ..base }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lacp_frame() {
        let mut p = vec![0x01, 0x01]; // subtype LACP, version 1
        p.extend_from_slice(&[0u8; 108]);
        let r = dissect_slow(&p);
        assert_eq!(r.protocol, Protocol::Lacp);
        assert_eq!(r.summary, "LACP v1 — link aggregation");
    }

    #[test]
    fn marker_frame() {
        let r = dissect_slow(&[0x02, 0x01]);
        assert_eq!(r.summary, "LACP Marker");
    }

    #[test]
    fn empty_is_safe() {
        let r = dissect_slow(&[]);
        assert!(r.summary.contains("empty"));
    }
}
