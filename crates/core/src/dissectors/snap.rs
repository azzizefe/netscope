// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! LLC/SNAP dispatch for 802.3 length-form frames.
//!
//! Frames whose EtherType field is really a length carry an 802.2 LLC header.
//! When its DSAP/SSAP are both 0xAA with control 0x03, a 5-byte SNAP header
//! follows: a 3-byte vendor OUI and a 2-byte protocol id. Cisco's control-plane
//! protocols (CDP, VTP, DTP, PAgP, UDLD) all live under OUI 00:00:0C.

use super::{cdp, dtp, pagp, udld, vtp, DissectedResult};

/// Cisco's OUI, under which its control protocols are registered.
const OUI_CISCO: [u8; 3] = [0x00, 0x00, 0x0C];

/// Parse an LLC/SNAP header and hand the payload to the right dissector.
/// Returns `None` when the frame isn't SNAP or the protocol id is unknown, so
/// the caller can fall back to a generic 802.3 summary.
pub fn dissect_snap(payload: &[u8]) -> Option<DissectedResult> {
    // LLC: DSAP, SSAP, control — SNAP is signalled by AA AA 03.
    if payload.len() < 8 || payload[0] != 0xAA || payload[1] != 0xAA || payload[2] != 0x03 {
        return None;
    }
    let oui = [payload[3], payload[4], payload[5]];
    let pid = u16::from_be_bytes([payload[6], payload[7]]);
    let body = &payload[8..];

    if oui != OUI_CISCO {
        return None;
    }
    match pid {
        0x2000 => Some(cdp::dissect_cdp(body)),
        0x2003 => Some(vtp::dissect_vtp(body)),
        0x2004 => Some(dtp::dissect_dtp(body)),
        0x0104 => Some(pagp::dissect_pagp(body)),
        0x0111 => Some(udld::dissect_udld(body)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Protocol;

    fn snap_frame(pid: u16, body: &[u8]) -> Vec<u8> {
        let mut p = vec![0xAA, 0xAA, 0x03];
        p.extend_from_slice(&OUI_CISCO);
        p.extend_from_slice(&pid.to_be_bytes());
        p.extend_from_slice(body);
        p
    }

    #[test]
    fn routes_cisco_protocol_ids() {
        let r = dissect_snap(&snap_frame(0x2000, &[0x02, 0xB4, 0x00, 0x00])).unwrap();
        assert_eq!(r.protocol, Protocol::Cdp);
        let r = dissect_snap(&snap_frame(0x2004, &[0x01])).unwrap();
        assert_eq!(r.protocol, Protocol::Dtp);
    }

    #[test]
    fn rejects_non_snap_and_foreign_ouis() {
        assert!(dissect_snap(&[0x42, 0x42, 0x03, 0, 0, 0, 0, 0]).is_none());
        let mut foreign = vec![0xAA, 0xAA, 0x03, 0x00, 0x11, 0x22];
        foreign.extend_from_slice(&0x2000u16.to_be_bytes());
        assert!(dissect_snap(&foreign).is_none());
    }
}
