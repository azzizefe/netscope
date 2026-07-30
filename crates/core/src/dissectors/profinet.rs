// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 azzizefe. All rights reserved.
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

    // A FrameID in the cyclic-IO range can carry a PROFIsafe payload inside the
    // ordinary one, so the framing decides rather than the range alone.
    if let Some(id) = frame_id {
        if (0x8000..=0xBBFF).contains(&id) && super::profisafe::looks_like_profisafe(&payload[2..])
        {
            return super::profisafe::dissect_profisafe(&payload[2..]);
        }
    }

    // The low FrameIDs are isochronous real-time — RT Class 3, the scheduled
    // traffic a synchronised line depends on. Nothing claimed this range, so
    // an IRT frame read as a generic "PROFINET frame" lost the one thing worth
    // knowing about it: which isochronous class it belongs to.
    if let Some(id) = frame_id.filter(|&id| id <= 0x01FF) {
        let _ = id;
        return super::profinet_irt_siemens::dissect_profinet_irt_siemens(
            None, None, 0, 0, payload,
        );
    }

    // Siemens puts its alarm and diagnosis channels inside the ordinary alarm
    // FrameIDs, numbered 0xA0 and 0xA1. The channel number is what says the
    // frame carries a Siemens-specific channel rather than a standard alarm,
    // so it decides — an alarm from another vendor's device stays a plain
    // PROFINET alarm.
    if let Some(id) = frame_id {
        if matches!(id, 0xFC01 | 0xFE01) && matches!(payload.get(2), Some(0xA0 | 0xA1)) {
            return super::profinet_rt_siemens::dissect_profinet_rt_siemens(
                None, None, 0, 0, payload,
            );
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

    /// The low FrameIDs are isochronous traffic — the scheduled frames a
    /// synchronised line runs on. Nothing claimed the range, so every one of
    /// them read as an unnamed "PROFINET frame".
    #[test]
    fn the_low_frame_ids_are_isochronous_real_time() {
        for id in [0x0000u16, 0x0080, 0x0100, 0x01FF] {
            let mut p = id.to_be_bytes().to_vec();
            p.extend_from_slice(&[0u8; 10]);
            let r = dissect_profinet(&p);
            assert_eq!(r.protocol, Protocol::ProfinetIrtSiemens, "{id:#06x}");
        }
        // Just past the range is not isochronous.
        let mut p = 0x0200u16.to_be_bytes().to_vec();
        p.extend_from_slice(&[0u8; 10]);
        assert_eq!(dissect_profinet(&p).protocol, Protocol::Profinet);
    }

    /// The Siemens channel number is what distinguishes a Siemens alarm from
    /// any other vendor's — the FrameID alone is shared, so it cannot decide.
    #[test]
    fn only_a_siemens_channel_number_claims_the_alarm() {
        let siemens = [0xFC, 0x01, 0xA0, 0x00, 0x00, 0x00];
        assert_eq!(
            dissect_profinet(&siemens).protocol,
            Protocol::ProfinetRtSiemens
        );

        // Same alarm FrameID, a channel number Siemens does not use: it stays
        // a plain PROFINET alarm rather than being attributed to Siemens.
        let other = [0xFC, 0x01, 0x07, 0x00, 0x00, 0x00];
        let r = dissect_profinet(&other);
        assert_eq!(r.protocol, Protocol::Profinet);
        assert!(r.summary.contains("Alarm (high priority)"), "{}", r.summary);
    }
}
