// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// CFM opcodes (IEEE 802.1ag §21.4, extended by ITU-T Y.1731 for the
/// performance-measurement messages).
fn opcode_name(op: u8) -> Option<&'static str> {
    Some(match op {
        1 => "CCM (continuity check)",
        3 => "LBR (loopback reply)",
        4 => "LBM (loopback message)",
        5 => "LTR (linktrace reply)",
        6 => "LTM (linktrace message)",
        32 => "AIS (alarm indication)",
        33 => "LCK (locked signal)",
        35 => "TST (test signal)",
        37 => "APS (protection switching)",
        39 => "MCC (maintenance communication)",
        40 => "LMM (loss measurement message)",
        41 => "LMR (loss measurement reply)",
        42 => "1DM (one-way delay)",
        43 => "DMM (delay measurement message)",
        44 => "DMR (delay measurement reply)",
        45 => "EXM (experimental message)",
        46 => "EXR (experimental reply)",
        47 => "VSM (vendor-specific message)",
        48 => "VSR (vendor-specific reply)",
        _ => return None,
    })
}

/// The common header: maintenance level and version, opcode, flags, then the
/// offset of the first TLV (802.1ag §21.4).
const HEADER: usize = 4;

/// Dissect a CFM frame — Connectivity Fault Management, the operations and
/// maintenance layer for carrier Ethernet (IEEE 802.1ag / ITU-T Y.1731).
///
/// A carrier selling an Ethernet circuit has to prove it is up and meeting its
/// latency commitment. CFM is how: continuity check messages flow constantly so
/// a break is noticed in milliseconds, and delay and loss measurement messages
/// produce the numbers a service level agreement is judged against.
///
/// The maintenance level is what keeps the customer's own monitoring separate
/// from the carrier's — each operates at its own level and ignores the others.
pub fn dissect_cfm(payload: &[u8]) -> DissectedResult {
    let result = |summary: String| DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Cfm,
        summary,
    };
    if payload.len() < HEADER {
        return result(format!("CFM ({})", super::bytes(payload.len() as u64)));
    }
    // The maintenance level is the top three bits; the version the low five.
    let level = payload[0] >> 5;
    let opcode = payload[1];
    match opcode_name(opcode) {
        Some(name) => result(format!("CFM {name} — level {level}")),
        None => result(format!("CFM opcode {opcode} — level {level}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a CFM header at the given maintenance level.
    fn cfm(level: u8, opcode: u8) -> Vec<u8> {
        // Version 0 in the low five bits, maintenance level in the top three.
        vec![level << 5, opcode, 0x00, 0x04]
    }

    #[test]
    fn continuity_check_names_its_level() {
        let r = dissect_cfm(&cfm(5, 1));
        assert_eq!(r.protocol, Protocol::Cfm);
        assert_eq!(r.summary, "CFM CCM (continuity check) — level 5");
    }

    /// The measurement messages are what a service level agreement is judged on.
    #[test]
    fn delay_and_loss_measurement_are_named() {
        assert_eq!(
            dissect_cfm(&cfm(3, 43)).summary,
            "CFM DMM (delay measurement message) — level 3"
        );
        assert_eq!(
            dissect_cfm(&cfm(3, 40)).summary,
            "CFM LMM (loss measurement message) — level 3"
        );
    }

    #[test]
    fn fault_notifications_are_named() {
        assert_eq!(
            dissect_cfm(&cfm(7, 32)).summary,
            "CFM AIS (alarm indication) — level 7"
        );
        assert_eq!(
            dissect_cfm(&cfm(7, 33)).summary,
            "CFM LCK (locked signal) — level 7"
        );
    }

    /// The level occupies only the top three bits; reading the whole byte would
    /// mix the version in and report a nonsensical level.
    #[test]
    fn level_excludes_the_version_bits() {
        let mut p = cfm(2, 1);
        p[0] |= 0x1F; // set every version bit
        assert_eq!(
            dissect_cfm(&p).summary,
            "CFM CCM (continuity check) — level 2"
        );
    }

    /// Levels run 0 to 7, and the customer and carrier use different ones.
    #[test]
    fn every_level_is_representable() {
        for level in 0..=7u8 {
            let r = dissect_cfm(&cfm(level, 1));
            assert!(r.summary.ends_with(&format!("level {level}")));
        }
    }

    #[test]
    fn unknown_opcode_reports_its_number() {
        let r = dissect_cfm(&cfm(4, 99));
        assert_eq!(r.summary, "CFM opcode 99 — level 4");
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_cfm(&[0xA0, 0x01]);
        assert_eq!(r.summary, "CFM (2 bytes)");
    }
}
