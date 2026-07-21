// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! SRv6 — the packet carrying its own itinerary (RFC 8754).
//!
//! Ordinary routing asks every hop to decide independently where a packet goes
//! next. Segment routing puts the decision in the packet instead: the ingress
//! node writes a list of segments — waypoints, really — into a Segment Routing
//! Header, and each listed node forwards to the next one. No hop in between
//! needs to hold any per-flow state, which is the whole point.
//!
//! The list is stored **backwards**. Segment List[0] is the *final* segment,
//! and `Segments Left` counts down as the packet is steered, so the segment
//! being aimed at right now is the one at index `Segments Left`.
//!
//! That counter is what makes a capture readable. It says how far along its
//! engineered path the packet has got, so seeing the same packet at two points
//! with the same count means it went somewhere the policy did not intend, and a
//! count that never decreases is a segment that is not being consumed — traffic
//! looping through a waypoint instead of past it. Neither is visible from the
//! addresses alone, because the outer destination is only ever the *next*
//! waypoint rather than the real one.

use std::net::Ipv6Addr;

/// The IPv6 fixed header, before any extension headers.
const IPV6_HEADER_LEN: usize = 40;
/// The routing header's own protocol number.
const EXT_ROUTING: u8 = 43;
/// Routing type 4 is segment routing; the other types are unrelated.
const ROUTING_TYPE_SRH: u8 = 4;
/// Each segment is a full IPv6 address.
const SEGMENT_LEN: usize = 16;
/// A chain longer than this is not something a real packet does.
const MAX_EXTENSION_HEADERS: usize = 8;

/// A parsed segment routing header.
pub(crate) struct Srh {
    /// How many waypoints are still to come.
    pub segments_left: u8,
    /// How many the policy listed in total.
    pub segment_count: u8,
    /// The waypoint being aimed at now, if it is present in the capture.
    pub active: Option<Ipv6Addr>,
}

impl Srh {
    /// The summary prefix, in the shape MPLS uses for its label stack.
    pub(crate) fn note(&self) -> String {
        match self.active {
            Some(active) => format!(
                "SRv6 segment {} of {} → {active}",
                self.segments_left, self.segment_count
            ),
            None => format!(
                "SRv6 segment {} of {}",
                self.segments_left, self.segment_count
            ),
        }
    }
}

/// Find the segment routing header in an IPv6 packet, if it has one.
///
/// Walks the extension chain using the same length rule as [`super::ip`] — the
/// authentication header measures itself differently from the rest, and a
/// second copy of that rule would eventually disagree with the first.
pub(crate) fn find(packet: &[u8]) -> Option<Srh> {
    let mut next_header = *packet.get(6)?;
    let mut rest = packet.get(IPV6_HEADER_LEN..)?;

    for _ in 0..MAX_EXTENSION_HEADERS {
        let length = super::ip::ext_header_len(next_header, rest)?;
        if next_header == EXT_ROUTING && rest.get(2) == Some(&ROUTING_TYPE_SRH) {
            // Bounded by the declared length when the whole header is present,
            // but a capture cut short by a snaplen still has the counters — and
            // those are the part worth reading, so it is not required.
            return parse(rest.get(..length).unwrap_or(rest));
        }
        next_header = *rest.first()?;
        rest = rest.get(length..)?;
    }
    None
}

/// Read the header's own fields, once it is known to be one.
fn parse(srh: &[u8]) -> Option<Srh> {
    let segments_left = *srh.get(3)?;
    // "Last Entry" is the highest index, so the count is one more than it.
    let segment_count = srh.get(4)?.checked_add(1)?;

    // The list runs backwards, so the active waypoint sits at the index the
    // counter names — not at the front, and not at the end.
    let active = srh
        .get(8 + segments_left as usize * SEGMENT_LEN..)
        .and_then(|s| s.get(..SEGMENT_LEN))
        .map(|bytes| {
            let mut octets = [0u8; SEGMENT_LEN];
            octets.copy_from_slice(bytes);
            Ipv6Addr::from(octets)
        });

    Some(Srh {
        segments_left,
        segment_count,
        active,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an IPv6 packet whose only extension header is an SRH.
    fn packet(segments_left: u8, segments: &[u8]) -> Vec<u8> {
        let count = segments.len();
        let mut srh = vec![
            59,                               // next header: none
            ((8 + count * 16) / 8 - 1) as u8, // header ext len
            ROUTING_TYPE_SRH,                 // routing type
            segments_left,                    // segments left
            (count - 1) as u8,                // last entry
            0x00,                             // flags
            0x00,                             // tag
            0x00,
        ];
        for &lead in segments {
            let mut addr = [0u8; 16];
            addr[0] = 0x20;
            addr[1] = 0x01;
            addr[15] = lead;
            srh.extend_from_slice(&addr);
        }

        let mut p = vec![0x60, 0, 0, 0];
        p.extend_from_slice(&(srh.len() as u16).to_be_bytes());
        p.push(EXT_ROUTING);
        p.push(64);
        p.extend_from_slice(&[0x20; 16]); // source
        p.extend_from_slice(&[0x30; 16]); // destination
        p.extend_from_slice(&srh);
        p
    }

    /// The reason this dissector exists: how far along its engineered path the
    /// packet has got, which the addresses alone never say.
    #[test]
    fn the_progress_through_the_segment_list_is_reported() {
        let srh = find(&packet(2, &[0xAA, 0xBB, 0xCC])).expect("an SRH");
        assert_eq!(srh.segments_left, 2);
        assert_eq!(srh.segment_count, 3);
        assert_eq!(srh.note(), "SRv6 segment 2 of 3 → 2001::cc");
    }

    /// The list is stored backwards, so the active waypoint is at the index the
    /// counter names. Reading the front of the list gives the *last* hop
    /// instead of the next one.
    #[test]
    fn the_active_segment_is_indexed_by_the_counter_not_taken_from_the_front() {
        let segments = [0xAA, 0xBB, 0xCC];
        // Segments Left 0 means the final waypoint, which is Segment List[0].
        let last = find(&packet(0, &segments)).expect("an SRH");
        assert_eq!(last.active.unwrap().to_string(), "2001::aa");
        // Segments Left 2 is the first waypoint, at the far end of the list.
        let first = find(&packet(2, &segments)).expect("an SRH");
        assert_eq!(first.active.unwrap().to_string(), "2001::cc");
    }

    /// Only routing type 4 is segment routing; the others are different
    /// protocols that happen to share the routing header.
    #[test]
    fn another_routing_type_is_not_claimed() {
        let mut p = packet(1, &[0xAA, 0xBB]);
        // Routing type sits at offset 2 of the extension header.
        p[IPV6_HEADER_LEN + 2] = 3;
        assert!(find(&p).is_none());
    }

    /// A packet with no routing header at all is not an SRv6 packet.
    #[test]
    fn a_packet_without_a_routing_header_is_not_claimed() {
        let mut p = vec![0x60, 0, 0, 0, 0, 8, 59, 64];
        p.extend_from_slice(&[0x20; 16]);
        p.extend_from_slice(&[0x30; 16]);
        assert!(find(&p).is_none());
        assert!(find(&[]).is_none());
        assert!(find(&[0x60; 20]).is_none());
    }

    /// A truncated segment list still reports the counters, which are the part
    /// that matters; it just cannot name the waypoint.
    #[test]
    fn a_truncated_segment_list_still_reports_the_counters() {
        let mut p = packet(2, &[0xAA, 0xBB, 0xCC]);
        p.truncate(IPV6_HEADER_LEN + 16);
        let srh = find(&p).expect("an SRH");
        assert_eq!(srh.segments_left, 2);
        assert!(srh.active.is_none());
        assert_eq!(srh.note(), "SRv6 segment 2 of 3");
    }

    /// A counter pointing past the end of the list is malformed and must not
    /// read some other part of the packet as an address.
    #[test]
    fn a_counter_past_the_end_of_the_list_names_no_waypoint() {
        let mut p = packet(1, &[0xAA, 0xBB]);
        p[IPV6_HEADER_LEN + 3] = 200;
        let srh = find(&p).expect("an SRH");
        assert_eq!(srh.segments_left, 200);
        assert!(srh.active.is_none());
    }
}
