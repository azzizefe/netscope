// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! MTP3 — the network layer that still routes the phone network.
//!
//! Beneath SCCP, ISUP and everything else in SS7 sits Message Transfer Part
//! level 3: the layer that decides which signalling point a message goes to.
//! Modern deployments carry it over IP via [`super::m2pa`] and [`super::m2ua`]
//! rather than over TDM links, but the routing label inside is unchanged, and
//! it is where two questions are answered that nothing above can answer.
//!
//! ## Which destination stopped being reachable
//!
//! Service indicator 0 is signalling network management — the network talking
//! about itself. A *transfer prohibited* message says a signalling point is no
//! longer reachable through this route. Calls to everything behind it will fail,
//! and the layers above see only timeouts: ISUP waits, SCCP retries, an
//! application reports "network error". The reason exists here and nowhere
//! else.
//!
//! ## What the message actually is
//!
//! The service indicator names the user part — SCCP, ISUP, TUP, BICC. A capture
//! that shows only "MTP3" for everything hides the difference between call
//! setup and database queries riding the same links.
//!
//! ## The routing label is little-endian, and its fields straddle bytes
//!
//! The label is one 32-bit **little-endian** word holding a 14-bit destination,
//! a 14-bit origin and a 4-bit link selector — none of which are byte-aligned.
//! Reading it big-endian, or reading the point codes as 16-bit values, produces
//! point codes that look like real ones. On a network where point codes are
//! assigned by a regulator and mean specific operators, a wrong one sends the
//! investigation to a different company.

use crate::models::Protocol;

use super::DissectedResult;

/// Service information octet, then the routing label.
const ITU_HEADER: usize = 5;

/// The user parts a message can belong to.
fn service_indicator(si: u8) -> &'static str {
    match si {
        0x0 => "network management",
        0x1 => "maintenance",
        0x2 => "maintenance (special)",
        0x3 => "SCCP",
        0x4 => "TUP",
        0x5 => "ISUP",
        0x6 => "DUP (call/circuit)",
        0x7 => "DUP (facility)",
        0x8 => "MTP test",
        0x9 => "broadband ISUP",
        0xA => "satellite ISUP",
        0xC => "AAL type 2 signalling",
        0xD => "BICC",
        0xE => "gateway control",
        _ => "spare",
    }
}

/// Whether the network is national or international decides how point codes
/// are interpreted, so two points with the same number in different networks
/// are different points.
fn network_indicator(ni: u8) -> &'static str {
    match ni {
        0 => "international",
        1 => "international (spare)",
        2 => "national",
        _ => "national (reserved)",
    }
}

/// Dissect an MTP3 message (ITU routing label).
pub(crate) fn describe(payload: &[u8]) -> String {
    let Some(head) = payload.get(..ITU_HEADER) else {
        return format!("MTP3 ({})", super::bytes(payload.len() as u64));
    };
    let si = head[0] & 0x0F;
    let ni = (head[0] & 0xC0) >> 6;

    // One little-endian word holds all three routing fields, none of them
    // aligned to a byte.
    let label = u32::from_le_bytes([head[1], head[2], head[3], head[4]]);
    let dpc = label & 0x0000_3FFF;
    let opc = (label & 0x0FFF_C000) >> 14;
    let sls = (label & 0xF000_0000) >> 28;

    let route = format!("{} → {dpc} (from {opc}, link {sls})", network_indicator(ni));

    // Network management is the layer talking about its own reachability, and
    // it is the only place a lost destination is explained rather than timed
    // out.
    if si == 0 {
        if let Some(&h0) = payload.get(ITU_HEADER) {
            // The heading code is the low nibble; the message within it the high.
            let heading = h0 & 0x0F;
            let message = (h0 & 0xF0) >> 4;
            if let Some(name) = management_message(heading, message) {
                return format!("MTP3 {name} — {route}");
            }
        }
        return format!("MTP3 network management — {route}");
    }

    format!("MTP3 {} — {route}", service_indicator(si))
}

/// The network management messages worth naming: the ones that say a route is
/// gone, or has come back.
fn management_message(heading: u8, message: u8) -> Option<&'static str> {
    Some(match (heading, message) {
        // Changeover / changeback, which move traffic between links.
        (0x1, 0x1) => "changeover order",
        (0x1, 0x2) => "changeover acknowledgement",
        (0x2, 0x5) => "changeback declaration",
        (0x2, 0x6) => "changeback acknowledgement",
        // The prohibited/allowed pair is the reachability answer.
        (0x4, 0x1) => "TRANSFER PROHIBITED — a destination became unreachable",
        (0x4, 0x2) => "transfer allowed — a destination came back",
        (0x4, 0x3) => "transfer restricted",
        (0x5, 0x1) => "transfer controlled (congestion)",
        (0x3, 0x1) => "emergency changeover order",
        (0x7, 0x1) => "traffic restart allowed",
        _ => return None,
    })
}

/// Dissect an MTP3 message reached on its own.
pub fn dissect_mtp3(payload: &[u8]) -> DissectedResult {
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Mtp3,
        summary: describe(payload),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an MTP3 message with an ITU routing label.
    fn mtp3(ni: u8, si: u8, dpc: u32, opc: u32, sls: u32, rest: &[u8]) -> Vec<u8> {
        let mut v = vec![(ni << 6) | si];
        let label = (dpc & 0x3FFF) | ((opc & 0x3FFF) << 14) | ((sls & 0x0F) << 28);
        v.extend_from_slice(&label.to_le_bytes());
        v.extend_from_slice(rest);
        v
    }

    /// The reason this dissector exists: everything above MTP3 sees only
    /// timeouts, and the explanation lives here.
    #[test]
    fn a_prohibited_destination_is_named() {
        let r = dissect_mtp3(&mtp3(2, 0, 1234, 5678, 3, &[0x14]));
        assert_eq!(r.protocol, Protocol::Mtp3);
        assert_eq!(
            r.summary,
            "MTP3 TRANSFER PROHIBITED — a destination became unreachable \
— national → 1234 (from 5678, link 3)"
        );
    }

    /// A destination coming back is as important as one going away.
    #[test]
    fn the_reachability_pair_is_distinguished() {
        let gone = describe(&mtp3(2, 0, 1, 2, 0, &[0x14]));
        let back = describe(&mtp3(2, 0, 1, 2, 0, &[0x24]));
        assert!(gone.contains("PROHIBITED"), "{gone}");
        assert!(back.contains("came back"), "{back}");
        assert_ne!(gone, back);
    }

    /// The user parts share the links, and a capture that calls them all
    /// "MTP3" hides the difference between call setup and database queries.
    #[test]
    fn the_user_parts_are_named() {
        assert!(describe(&mtp3(2, 0x3, 1, 2, 0, &[])).contains("SCCP"));
        assert!(describe(&mtp3(2, 0x5, 1, 2, 0, &[])).contains("ISUP"));
        assert!(describe(&mtp3(2, 0x4, 1, 2, 0, &[])).contains("TUP"));
        assert!(describe(&mtp3(2, 0xD, 1, 2, 0, &[])).contains("BICC"));
    }

    /// The label is little-endian. Read the other way the point codes are
    /// still plausible numbers, which on a regulated network sends an
    /// investigation to a different operator.
    #[test]
    fn the_routing_label_is_little_endian() {
        let summary = describe(&mtp3(2, 0x5, 1234, 5678, 3, &[]));
        assert!(summary.contains("→ 1234"), "{summary}");
        assert!(summary.contains("from 5678"), "{summary}");

        // The big-endian reading of the same bytes is a different, and equally
        // believable, pair of point codes.
        let frame = mtp3(2, 0x5, 1234, 5678, 3, &[]);
        let swapped = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]);
        assert_ne!(swapped & 0x3FFF, 1234, "the wrong reading looks real");
    }

    /// The point codes are fourteen bits and do not align to bytes, so the
    /// full range has to survive the round trip.
    #[test]
    fn the_point_codes_are_fourteen_bits() {
        for (dpc, opc) in [(0u32, 0u32), (16383, 16383), (1, 16383), (16383, 1)] {
            let summary = describe(&mtp3(2, 0x5, dpc, opc, 0, &[]));
            assert!(summary.contains(&format!("→ {dpc} ")), "{summary}");
            assert!(summary.contains(&format!("from {opc},")), "{summary}");
        }
    }

    /// The link selector is the top four bits and must not bleed into the
    /// origin point code.
    #[test]
    fn the_link_selector_does_not_disturb_the_point_codes() {
        let plain = describe(&mtp3(2, 0x5, 100, 200, 0, &[]));
        let selected = describe(&mtp3(2, 0x5, 100, 200, 15, &[]));
        assert!(plain.contains("link 0") && selected.contains("link 15"));
        assert!(
            selected.contains("→ 100") && selected.contains("from 200"),
            "{selected}"
        );
    }

    /// A national and an international point code of the same number are
    /// different points.
    #[test]
    fn the_network_indicator_is_reported() {
        assert!(describe(&mtp3(0, 0x5, 1, 2, 0, &[])).contains("international"));
        assert!(describe(&mtp3(2, 0x5, 1, 2, 0, &[])).contains("national"));
    }

    /// An unrecognised management message is still management.
    #[test]
    fn an_unknown_management_message_is_not_guessed_at() {
        let summary = describe(&mtp3(2, 0, 1, 2, 0, &[0xFF]));
        assert_eq!(
            summary,
            "MTP3 network management — national → 1 (from 2, link 0)"
        );
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "MTP3 (0 bytes)");
        assert_eq!(describe(&[0x83, 0x01, 0x02, 0x03]), "MTP3 (4 bytes)");
        // Network management with no heading code after the label.
        assert!(describe(&mtp3(2, 0, 1, 2, 0, &[])).contains("network management"));
    }
}
