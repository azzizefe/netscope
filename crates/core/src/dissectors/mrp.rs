// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! MRP — the ring that keeps a factory running (IEC 62439-2).
//!
//! Industrial networks are wired as rings so that one cut cable does not stop
//! the line. A manager sits at the top of the ring, sends test frames both ways
//! round, and keeps one port blocked so the ring is not a loop. When the tests
//! stop arriving it opens that port, and the network reconverges in tens of
//! milliseconds.
//!
//! That reconvergence is what to look for. A ring that changes topology once is
//! a cable being replaced; a ring that changes repeatedly is a connection
//! failing intermittently, and the machines on it will be dropping cycles
//! without anything else in the capture saying so.

use crate::models::Protocol;

use super::DissectedResult;

/// Every MRP frame opens with a version, then a type-length-value sequence.
const HEADER_LEN: usize = 2;

/// What a frame is doing. Only the types the standard defines are named.
fn frame_name(kind: u8) -> Option<&'static str> {
    Some(match kind {
        0x01 => "end of TLV list",
        0x02 => "common header",
        0x03 => "test frame",
        0x04 => "topology change",
        0x05 => "link down",
        0x06 => "link up",
        0x07 => "interconnect test",
        0x08 => "interconnect topology change",
        0x09 => "interconnect link down",
        0x0A => "interconnect link up",
        0x0B => "interconnect status poll",
        0x7F => "option",
        _ => return None,
    })
}

/// The ring's state, carried by test frames.
fn ring_state(state: u8) -> &'static str {
    match state {
        0x00 => "open",
        0x01 => "closed",
        _ => "unknown state",
    }
}

/// The role a node plays.
fn role_name(role: u16) -> &'static str {
    match role {
        0x0000 => "client",
        0x0001 => "manager",
        0x0002 => "auto-manager",
        _ => "node",
    }
}

/// Dissect an MRP frame (EtherType 0x88E3).
pub fn dissect_mrp(payload: &[u8]) -> DissectedResult {
    let base = DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Mrp,
        summary: String::new(),
    };
    DissectedResult {
        summary: describe(payload),
        ..base
    }
}

fn describe(payload: &[u8]) -> String {
    // Version, then the first TLV: type, length, value.
    let Some(&kind) = payload.get(HEADER_LEN) else {
        return "MRP frame".to_string();
    };
    let name = match frame_name(kind) {
        Some(n) => n,
        None => return format!("MRP frame (type 0x{kind:02x})"),
    };

    let body = payload.get(HEADER_LEN + 2..).unwrap_or(&[]);
    match kind {
        // A test frame carries the ring's state and the sender's role, which
        // together say whether the ring is currently whole.
        0x03 => {
            let state = body.first().copied().unwrap_or(0xFF);
            let role = body
                .get(1..3)
                .map(|b| u16::from_be_bytes([b[0], b[1]]))
                .unwrap_or(0xFFFF);
            format!(
                "MRP test — ring {} (from the {})",
                ring_state(state),
                role_name(role)
            )
        }
        // A topology change is the ring reconverging: something broke or came
        // back, and every node is about to flush what it learned.
        0x04 => {
            let interval = body
                .get(2..4)
                .map(|b| u16::from_be_bytes([b[0], b[1]]))
                .unwrap_or(0);
            format!("MRP topology change — reconverging in {interval} ms")
        }
        0x05 | 0x06 => {
            let direction = if kind == 0x05 { "down" } else { "up" };
            format!("MRP link {direction}")
        }
        _ => format!("MRP {name}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an MRP frame carrying one TLV.
    fn frame(kind: u8, value: &[u8]) -> Vec<u8> {
        let mut p = vec![0x00, 0x01]; // version 1
        p.push(kind);
        p.push(value.len() as u8);
        p.extend_from_slice(value);
        p
    }

    /// The everyday frame: the manager testing that the ring is whole.
    #[test]
    fn a_test_frame_reports_the_ring_state_and_who_sent_it() {
        // Ring closed, sent by the manager.
        let p = frame(0x03, &[0x01, 0x00, 0x01, 0, 0, 0]);
        let r = dissect_mrp(&p);
        assert_eq!(r.protocol, Protocol::Mrp);
        assert_eq!(r.summary, "MRP test — ring closed (from the manager)");
    }

    /// A ring that has opened is a ring with a break in it, and the whole point
    /// of the protocol is that this is visible.
    #[test]
    fn an_open_ring_is_reported_as_open() {
        let p = frame(0x03, &[0x00, 0x00, 0x00, 0, 0, 0]);
        assert!(dissect_mrp(&p).summary.contains("ring open"));
    }

    /// Topology changes are the interesting event: one is a cable being
    /// replaced, a stream of them is a connection failing intermittently.
    #[test]
    fn a_topology_change_gives_its_reconvergence_time() {
        // Two bytes of prefix, then the interval.
        let p = frame(0x04, &[0x00, 0x00, 0x00, 0x14]);
        assert_eq!(
            dissect_mrp(&p).summary,
            "MRP topology change — reconverging in 20 ms"
        );
    }

    #[test]
    fn link_events_are_named() {
        assert_eq!(dissect_mrp(&frame(0x05, &[])).summary, "MRP link down");
        assert_eq!(dissect_mrp(&frame(0x06, &[])).summary, "MRP link up");
    }

    /// A type outside the standard keeps its number rather than being mapped to
    /// whichever entry was nearest.
    #[test]
    fn an_unknown_frame_type_keeps_its_number() {
        assert_eq!(
            dissect_mrp(&frame(0x42, &[])).summary,
            "MRP frame (type 0x42)"
        );
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(dissect_mrp(&[]).summary, "MRP frame");
        assert_eq!(dissect_mrp(&[0x00, 0x01]).summary, "MRP frame");
        // A test frame with no body must not read past it.
        assert!(dissect_mrp(&frame(0x03, &[]))
            .summary
            .starts_with("MRP test"));
    }
}
