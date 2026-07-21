// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a PROFINET frame (EtherType 0x8892) — real-time industrial
/// automation (PLCs, IO devices). The first two bytes are the FrameID, whose
/// range selects the service (PROFINET IO / IEC 61158).
pub fn dissect_profinet(payload: &[u8]) -> DissectedResult {
    // DCP is a protocol in its own right — discovery and configuration rather
    // than cyclic IO — so it is relabelled and read properly instead of being
    // reported as a PROFINET frame with a service name.
    let frame_id = payload.get(..2).map(|b| u16::from_be_bytes([b[0], b[1]]));
    if frame_id.is_some_and(super::pn_dcp::is_dcp_frame) {
        return super::pn_dcp::dissect_pn_dcp(&payload[2..]);
    }
    // 0xFF00-0xFF43 is the clock protocol, not cyclic IO. This range was
    // previously labelled "RT Class 3 (isochronous)", which is wrong — RT
    // Class 3 uses the low FrameIDs, and PTCP is what synchronises it.
    if let Some(id) = frame_id.filter(|&id| super::pn_ptcp::is_ptcp_frame(id)) {
        return super::pn_ptcp::dissect_pn_ptcp(id, &payload[2..]);
    }

    if let Some(id) = frame_id {
        if (0x8000..=0xBBFF).contains(&id) && super::profisafe::looks_like_profisafe(&payload[2..]) {
            return super::profisafe::dissect_profisafe(&payload[2..]);
        }
    }

    let summary = if payload.len() >= 2 {
        let frame_id = u16::from_be_bytes([payload[0], payload[1]]);
        let name = match frame_id {
            0xFC01 => "Alarm (high priority)",
            0xFE01 => "Alarm (low priority)",
            f if (0x8000..=0xBBFF).contains(&f) => "RT Class 1 (cyclic data)",
            _ => "frame",
        };
        format!("PROFINET {name}")
    } else {
        "PROFINET (truncated)".to_string()
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Profinet,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A DCP FrameID hands the frame to the DCP dissector, which relabels it —
    /// discovery and configuration is a different job from cyclic IO.
    #[test]
    fn dcp_identify_is_handed_to_the_dcp_dissector() {
        let mut p = vec![0xFE, 0xFC];
        p.extend_from_slice(&[0x05, 0x00, 0, 0, 0, 0, 0, 0, 0, 0]);
        let r = dissect_profinet(&p);
        assert_eq!(r.protocol, Protocol::PnDcp);
        assert_eq!(r.summary, "PROFINET DCP Identify");
    }

    /// Everything outside those ranges stays PROFINET.
    #[test]
    fn a_non_dcp_frame_id_is_not_relabelled() {
        let r = dissect_profinet(&[0xFC, 0x01, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Profinet);
        assert!(r.summary.contains("Alarm (high priority)"), "{}", r.summary);
    }

    /// 0xFF00-0xFF43 is the clock protocol. It used to be reported as
    /// "RT Class 3 (isochronous)", which was simply the wrong range — RT
    /// Class 3 lives in the low FrameIDs.
    #[test]
    fn the_clock_range_is_ptcp_not_rt_class_3() {
        for id in [0xFF00u16, 0xFF20, 0xFF43] {
            let mut p = id.to_be_bytes().to_vec();
            p.extend_from_slice(&[0u8; 10]);
            let r = dissect_profinet(&p);
            assert_eq!(r.protocol, Protocol::PnPtcp, "{id:#06x}");
            assert!(!r.summary.contains("RT Class 3"), "{}", r.summary);
        }
        // Cyclic RT Class 1 is a real range and stays where it was.
        let r = dissect_profinet(&[0x80, 0x00, 0x00, 0x00]);
        assert!(r.summary.contains("RT Class 1"), "{}", r.summary);
    }

    #[test]
    fn cyclic_rt() {
        let r = dissect_profinet(&[0x80, 0x00, 0x00, 0x00]);
        assert!(r.summary.contains("RT Class 1"), "{}", r.summary);
    }

    #[test]
    fn profisafe_dispatch() {
        let p = vec![0x80, 0x00, 0x01, 0x02, 0x20, 0xAA, 0xBB, 0xCC];
        let r = dissect_profinet(&p);
        assert_eq!(r.protocol, Protocol::Profisafe);
        assert!(r.summary.contains("PROFIsafe"), "{}", r.summary);
    }
}
