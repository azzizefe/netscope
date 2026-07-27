// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// CFM opcodes (IEEE 802.1Q, extended by ITU-T G.8013/Y.1731 for the
/// performance-measurement messages).
///
/// The numbering has a trap in it: the standard assigns the **reply the lower
/// number** and the request the higher one, in every pair — LBR 0x02 before
/// LBM 0x03, LMR 0x2A before LMM 0x2B, DMR 0x2E before DMM 0x2F. Anyone who
/// writes the names out in the order they are usually *discussed* and numbers
/// them sequentially gets a table that is wrong from the second entry on. That
/// is exactly what this table used to be, which made netscope report a ring
/// protection switch as a loss measurement.
fn opcode_name(op: u8) -> Option<&'static str> {
    Some(match op {
        0x01 => "CCM (continuity check)",
        0x02 => "LBR (loopback reply)",
        0x03 => "LBM (loopback message)",
        0x04 => "LTR (linktrace reply)",
        0x05 => "LTM (linktrace message)",
        0x06 => "RFM (reflected frame)",
        0x07 => "SFM (send frame)",
        0x20 => "GNM (generic notification)",
        0x21 => "AIS (alarm indication)",
        0x23 => "LCK (locked signal)",
        0x25 => "TST (test signal)",
        0x27 => "APS (protection switching)",
        // 0x28 is R-APS, which is handled as its own protocol — see `erps`.
        0x29 => "MCC (maintenance communication)",
        0x2A => "LMR (loss measurement reply)",
        0x2B => "LMM (loss measurement message)",
        0x2D => "1DM (one-way delay)",
        0x2E => "DMR (delay measurement reply)",
        0x2F => "DMM (delay measurement message)",
        0x30 => "EXR (experimental reply)",
        0x31 => "EXM (experimental message)",
        0x32 => "VSR (vendor-specific reply)",
        0x33 => "VSM (vendor-specific message)",
        0x34 => "CSF (client signal fail)",
        0x35 => "1SL (one-way synthetic loss)",
        0x36 => "SLR (synthetic loss reply)",
        0x37 => "SLM (synthetic loss message)",
        _ => return None,
    })
}

/// The opcode that carries ring protection, which is a protocol of its own.
pub(crate) const OPCODE_RAPS: u8 = 0x28;

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
            dissect_cfm(&cfm(3, 0x2F)).summary,
            "CFM DMM (delay measurement message) — level 3"
        );
        assert_eq!(
            dissect_cfm(&cfm(3, 0x2B)).summary,
            "CFM LMM (loss measurement message) — level 3"
        );
    }

    /// In every request/reply pair the standard gives the **reply** the lower
    /// number. Numbering the names in the order they are usually discussed
    /// produces a table that is wrong from the second entry on — which is what
    /// this table was, and it made a ring protection switch read as a loss
    /// measurement.
    #[test]
    fn the_reply_is_numbered_below_the_request() {
        for (reply, request) in [
            (0x02u8, 0x03u8), // loopback
            (0x04, 0x05),     // linktrace
            (0x2A, 0x2B),     // loss measurement
            (0x2E, 0x2F),     // delay measurement
            (0x30, 0x31),     // experimental
            (0x32, 0x33),     // vendor-specific
            (0x36, 0x37),     // synthetic loss
        ] {
            let lower = opcode_name(reply).expect("a named opcode");
            let higher = opcode_name(request).expect("a named opcode");
            assert!(lower.contains("reply"), "{reply:#04x} is {lower}");
            assert!(
                higher.contains("message"),
                "{request:#04x} is {higher}, expected the request"
            );
        }
    }

    /// Ring protection is not an OAM message and is not claimed here.
    #[test]
    fn ring_protection_is_left_to_its_own_protocol() {
        assert_eq!(OPCODE_RAPS, 0x28);
        assert!(opcode_name(OPCODE_RAPS).is_none());
    }

    #[test]
    fn fault_notifications_are_named() {
        assert_eq!(
            dissect_cfm(&cfm(7, 0x21)).summary,
            "CFM AIS (alarm indication) — level 7"
        );
        assert_eq!(
            dissect_cfm(&cfm(7, 0x23)).summary,
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
