// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! ESMC — how a network distributes the quality of its clock (ITU-T G.8264).
//!
//! Synchronous Ethernet carries frequency in the physical layer, but a receiver
//! cannot tell from a clock signal alone how good that clock is. ESMC carries
//! that judgement separately: each hop announces the quality level of the source
//! it is locked to, and downstream equipment uses it to decide which port to
//! take timing from.
//!
//! The value in a capture is watching it degrade. A chain announcing PRC is
//! locked to a caesium-grade reference; the same chain announcing SEC has fallen
//! back to a local oscillator and will drift. Mobile basestations and
//! substations care about this long before anything else notices.
//!
//! # What this cannot tell you
//!
//! The quality codes are numbers whose meaning depends on which option the
//! network runs — Option 1 (ITU/ETSI) and Option 2 (ANSI) assign the same
//! values to different clocks, and nothing in the frame says which is in use.
//! Option 1 is named here because it is far more widely deployed, and the code
//! is always shown alongside so a reader on an Option 2 network is not misled.
//! The one value both agree on is 0xF: do not use this clock.

use crate::models::Protocol;

use super::DissectedResult;

/// The ITU-T organisation identifier that marks a slow protocol as ESMC.
pub(crate) const ITU_OUI: [u8; 3] = [0x00, 0x19, 0xA7];
/// The ITU subtype within that organisation.
const ITU_SUBTYPE: u16 = 0x0001;
/// The TLV carrying the quality level.
const TLV_QUALITY_LEVEL: u8 = 0x01;

/// An event flag means this frame is a change rather than the one-per-second
/// heartbeat, which is what makes it worth noticing.
const FLAG_EVENT: u8 = 0x08;

/// What a quality level means under Option 1, the common deployment.
fn quality_name(code: u8) -> Option<&'static str> {
    Some(match code {
        0x0 => "unknown quality",
        0x2 => "primary reference clock",
        0x4 => "type I synchronisation supply unit",
        0x8 => "type II synchronisation supply unit",
        0xB => "local equipment clock (will drift)",
        0xF => "do not use for synchronisation",
        _ => return None,
    })
}

/// Whether a slow-protocol frame is ESMC rather than another vendor's use of
/// the organisation-specific subtype.
pub(crate) fn is_esmc(payload: &[u8]) -> bool {
    payload.get(1..4) == Some(&ITU_OUI[..])
        && payload.get(4..6).map(|b| u16::from_be_bytes([b[0], b[1]])) == Some(ITU_SUBTYPE)
}

/// Dissect an ESMC frame. `payload` starts at the slow-protocol subtype.
pub(crate) fn result(payload: &[u8]) -> DissectedResult {
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Esmc,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    // Subtype, OUI (3), ITU subtype (2), then version and flags.
    let event = payload.get(6).is_some_and(|&flags| flags & FLAG_EVENT != 0);
    let kind = if event { "event" } else { "heartbeat" };

    // Four reserved bytes, then the quality-level TLV: type, length, value.
    let Some(tlv) = payload.get(11..15) else {
        return format!("ESMC {kind}");
    };
    if tlv[0] != TLV_QUALITY_LEVEL {
        return format!("ESMC {kind}");
    }
    // The quality sits in the low four bits of the TLV's last byte.
    let code = tlv[3] & 0x0F;
    match quality_name(code) {
        Some(name) => format!("ESMC {kind} — {name} (QL {code:X})"),
        None => format!("ESMC {kind} — QL {code:X}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an ESMC frame carrying a quality level.
    fn esmc(flags: u8, quality: u8) -> Vec<u8> {
        let mut p = vec![0x0A]; // organisation-specific slow protocol
        p.extend_from_slice(&ITU_OUI);
        p.extend_from_slice(&ITU_SUBTYPE.to_be_bytes());
        p.push(flags); // version and event flag
        p.extend_from_slice(&[0x00; 4]); // reserved
        p.extend_from_slice(&[TLV_QUALITY_LEVEL, 0x00, 0x04, quality]);
        p
    }

    /// The everyday frame: a hop announcing it is locked to a good reference.
    #[test]
    fn a_heartbeat_reports_the_quality_it_is_locked_to() {
        let r = result(&esmc(0x10, 0x02));
        assert_eq!(r.protocol, Protocol::Esmc);
        assert_eq!(r.summary, "ESMC heartbeat — primary reference clock (QL 2)");
    }

    /// The point of watching this: a chain that has fallen back to a local
    /// oscillator will drift, and says so here before anything else notices.
    #[test]
    fn a_degraded_chain_says_it_will_drift() {
        assert!(result(&esmc(0x10, 0x0B)).summary.contains("will drift"));
        assert!(result(&esmc(0x10, 0x0F))
            .summary
            .contains("do not use for synchronisation"));
    }

    /// An event frame is a change rather than the once-a-second heartbeat, and
    /// that is what makes it worth stopping on.
    #[test]
    fn an_event_is_distinguished_from_the_heartbeat() {
        assert!(result(&esmc(0x10 | FLAG_EVENT, 0x02))
            .summary
            .starts_with("ESMC event"));
        assert!(result(&esmc(0x10, 0x02))
            .summary
            .starts_with("ESMC heartbeat"));
    }

    /// The quality is four bits, not a whole byte. Reading the byte would turn
    /// every value into a number no table has.
    #[test]
    fn the_quality_is_read_from_the_low_nibble() {
        // 0xF2: reserved high nibble, quality 2.
        assert!(result(&esmc(0x10, 0xF2))
            .summary
            .contains("primary reference clock"));
        assert!(!result(&esmc(0x10, 0xF2)).summary.contains("QL F2"));
    }

    /// Another vendor may use the organisation-specific subtype for its own
    /// purposes, and reading that as a clock quality would be inventing.
    #[test]
    fn only_the_itu_organisation_identifier_is_claimed() {
        assert!(is_esmc(&esmc(0x10, 0x02)));
        // Cisco's OUI in the same position.
        let mut other = esmc(0x10, 0x02);
        other[1..4].copy_from_slice(&[0x00, 0x00, 0x0C]);
        assert!(!is_esmc(&other));
        assert!(!is_esmc(&[0x0A]));
        assert!(!is_esmc(&[]));
    }

    /// A code outside Option 1's table keeps its number, which matters here
    /// more than usual: an Option 2 network uses the same values differently.
    #[test]
    fn an_unnamed_quality_keeps_its_number() {
        assert_eq!(result(&esmc(0x10, 0x07)).summary, "ESMC heartbeat — QL 7");
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[0x0A]), "ESMC heartbeat");
        let mut short = esmc(0x10, 0x02);
        short.truncate(12);
        assert!(describe(&short).starts_with("ESMC"));
    }
}
