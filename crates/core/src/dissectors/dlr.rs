// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! DLR — Device Level Ring, ODVA's ring protection for EtherNet/IP.
//!
//! The same idea as [`super::erps`] solved for a different world. A ring of
//! devices on a machine — drives, I/O blocks, a controller — is wired as a loop
//! so a single cut cannot isolate anything, and one node, the ring supervisor,
//! keeps the loop from flooding by blocking a port. Recovery is in the low
//! milliseconds, because a machine in motion cannot pause while a network
//! reconverges.
//!
//! ## Why the beacon is the message that matters
//!
//! The supervisor emits beacons continuously, often every few hundred
//! microseconds, and the ring's health is inferred from their arrival rather
//! than announced. Two things in a beacon carry the diagnosis:
//!
//! * **Ring state** — normal, or fault. A ring sitting in fault state is still
//!   passing traffic (that is the whole point of the redundancy) while having
//!   spent it. Nothing on the machine notices until the second break.
//! * **Supervisor precedence** — which node won the election. Two supervisors
//!   configured on one ring is a common commissioning mistake, and it shows up
//!   here as beacons from two different addresses rather than as an error.
//!
//! **Sign_On** and **Announce** appear while the ring is forming. Seeing them
//! repeatedly on a ring that should be settled means it is re-forming — a
//! marginal cable or a device rebooting — which is invisible at the
//! application layer until the day it fails outright.
//!
//! ## The interval is byte-swapped relative to the CIP object
//!
//! The beacon interval and timeout appear both in the on-wire frame and as
//! attributes of the CIP DLR object, and the two use **opposite byte orders**:
//! big-endian here, little-endian in the object. Anyone implementing from the
//! object specification and testing against a capture will get a wildly wrong
//! number rather than a subtly wrong one — a 400 µs interval reads as about
//! forty minutes — so the mistake announces itself. It is recorded because the
//! contradiction is real and surprising, not because it is hard to notice.

use std::net::Ipv4Addr;

use crate::models::Protocol;

use super::DissectedResult;

/// Sub-type and protocol version, then the message payload fields.
const HEADER: usize = 2;
/// Frame type, source port, source address, sequence — the payload every DLR
/// frame carries.
const MINIMUM: usize = HEADER + 1 + 1 + 4 + 4;

fn frame_type(kind: u8) -> Option<&'static str> {
    Some(match kind {
        1 => "Beacon",
        2 => "Neighbor_Check_Request",
        3 => "Neighbor_Check_Response",
        4 => "Link_Status / Neighbor_Status",
        5 => "Locate_Fault",
        6 => "Announce",
        7 => "Sign_On",
        8 => "Advertise",
        9 => "Flush_Tables",
        10 => "Learning_Update",
        _ => return None,
    })
}

/// Dissect a DLR frame.
pub fn dissect_dlr(payload: &[u8]) -> DissectedResult {
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Dlr,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    if payload.len() < MINIMUM {
        return format!("DLR ({})", super::bytes(payload.len() as u64));
    }
    let kind = payload[2];
    let name = frame_type(kind)
        .map(str::to_string)
        .unwrap_or_else(|| format!("frame type {kind}"));

    // The source address says which node sent it, which is what turns "the
    // ring is re-forming" into a node to go and look at.
    let source = Ipv4Addr::new(payload[4], payload[5], payload[6], payload[7]);

    // Only a beacon carries the ring state; the other frames have their own
    // layouts, and reading a state byte out of them would invent a field.
    if kind == 1 {
        // State, precedence and a four-byte interval must all be present —
        // an empty tail would otherwise read as a beacon with no state.
        if let Some(rest) = payload.get(12..18) {
            let state = match rest[0] {
                1 => "ring normal",
                // Still forwarding, but the redundancy has been spent.
                2 => "RING FAULT — running without redundancy",
                _ => "ring state unknown",
            };
            let precedence = rest[1];
            // Big-endian on the wire, though the same value is little-endian
            // as a CIP object attribute.
            let interval = u32::from_be_bytes([rest[2], rest[3], rest[4], rest[5]]);
            return format!(
                "DLR Beacon — {state}, from {source} (precedence {precedence}, every {interval} µs)"
            );
        }
    }

    format!("DLR {name} from {source}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a DLR frame.
    fn dlr(kind: u8, source: [u8; 4]) -> Vec<u8> {
        let mut v = vec![0x02, 0x01]; // ring sub-type, protocol version
        v.push(kind);
        v.push(0x01); // source port
        v.extend_from_slice(&source);
        v.extend_from_slice(&7u32.to_be_bytes()); // sequence
        v
    }

    /// Build a beacon with the given ring state and precedence.
    fn beacon(state: u8, precedence: u8, interval_us: u32) -> Vec<u8> {
        let mut v = dlr(1, [192, 168, 1, 10]);
        v.push(state);
        v.push(precedence);
        // Interval and timeout are big-endian in the frame.
        v.extend_from_slice(&interval_us.to_be_bytes());
        v.extend_from_slice(&(interval_us * 4).to_be_bytes());
        v.extend_from_slice(&[0u8; 20]); // reserved
        v
    }

    /// The reason this dissector exists: a ring in fault state still carries
    /// traffic, so nothing on the machine reports it.
    #[test]
    fn a_ring_in_fault_state_is_called_out() {
        let r = dissect_dlr(&beacon(2, 5, 400));
        assert_eq!(r.protocol, Protocol::Dlr);
        assert_eq!(
            r.summary,
            "DLR Beacon — RING FAULT — running without redundancy, \
from 192.168.1.10 (precedence 5, every 400 µs)"
        );
    }

    #[test]
    fn a_healthy_ring_reads_as_normal() {
        let summary = describe(&beacon(1, 5, 400));
        assert!(summary.contains("ring normal"), "{summary}");
        assert!(!summary.contains("FAULT"), "{summary}");
    }

    /// Two supervisors on one ring is a commissioning mistake that shows up as
    /// beacons from two addresses, so the address and precedence both matter.
    #[test]
    fn the_beacon_names_its_supervisor_and_precedence() {
        let a = describe(&beacon(1, 5, 400));
        let mut other = beacon(1, 9, 400);
        other[4..8].copy_from_slice(&[192, 168, 1, 20]);
        let b = describe(&other);
        assert!(
            a.contains("192.168.1.10") && a.contains("precedence 5"),
            "{a}"
        );
        assert!(
            b.contains("192.168.1.20") && b.contains("precedence 9"),
            "{b}"
        );
    }

    /// Sign_On and Announce on a settled ring mean it is re-forming.
    #[test]
    fn the_ring_forming_frames_are_named() {
        assert!(describe(&dlr(7, [10, 0, 0, 1])).contains("Sign_On"));
        assert!(describe(&dlr(6, [10, 0, 0, 1])).contains("Announce"));
        assert!(describe(&dlr(5, [10, 0, 0, 1])).contains("Locate_Fault"));
    }

    /// Only a beacon has a ring state. Reading one out of another frame type
    /// would report a field that is not there.
    #[test]
    fn only_a_beacon_reports_a_ring_state() {
        // A Sign_On whose byte 12 would read as "fault" if it were a beacon.
        let mut sign_on = dlr(7, [10, 0, 0, 1]);
        sign_on.push(0x02);
        sign_on.extend_from_slice(&[0u8; 20]);
        let summary = describe(&sign_on);
        assert!(summary.contains("Sign_On"), "{summary}");
        assert!(!summary.contains("FAULT"), "{summary}");
        assert!(!summary.contains("ring"), "{summary}");
    }

    /// The payload fields start after the two-byte common header. Reading the
    /// frame type from offset 0 would report the ring sub-type instead.
    #[test]
    fn the_frame_type_follows_the_common_header() {
        let frame = dlr(1, [10, 0, 0, 1]);
        assert_eq!(frame[0], 0x02, "sub-type, not the frame type");
        assert_eq!(frame[2], 1, "the frame type is at offset 2");
        assert!(describe(&frame).contains("Beacon"));
    }

    /// The interval is big-endian in the frame, and little-endian as a CIP
    /// object attribute — the same field, opposite orders. Implementing from
    /// the object specification gives a number that is wrong by a factor of
    /// millions rather than subtly wrong.
    #[test]
    fn the_beacon_interval_is_big_endian() {
        let summary = describe(&beacon(1, 5, 400));
        assert!(summary.contains("every 400 µs"), "{summary}");
        let swapped = u32::from_le_bytes(400u32.to_be_bytes());
        assert_eq!(swapped, 2_415_984_640);
        assert!(!summary.contains(&swapped.to_string()), "{summary}");
    }

    #[test]
    fn an_unknown_frame_type_reports_its_number() {
        assert!(describe(&dlr(99, [10, 0, 0, 1])).contains("frame type 99"));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "DLR (0 bytes)");
        assert_eq!(describe(&[0x02, 0x01, 0x01]), "DLR (3 bytes)");
        // A beacon header with no state or interval after it falls back to
        // the generic form rather than reporting fields that are not there.
        assert_eq!(describe(&dlr(1, [10, 0, 0, 1])), "DLR Beacon from 10.0.0.1");
    }
}
