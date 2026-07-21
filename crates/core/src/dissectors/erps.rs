// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! ERPS — the ring that deliberately keeps one link switched off.
//!
//! A ring of Ethernet switches is a loop, and a loop floods itself to death.
//! ITU-T G.8032 solves it the way spanning tree does not: one designated link,
//! the ring protection link, is blocked on purpose, and the ring runs as a line.
//! When a link fails, that block is released and traffic reroutes the other way
//! around — in tens of milliseconds, which is what makes ERPS acceptable where
//! spanning tree's seconds are not.
//!
//! The coordination messages are R-APS, carried as an opcode inside the CFM
//! frame format (EtherType 0x8902).
//!
//! ## What the messages mean
//!
//! * **Signal Fail** — a node has lost a link and is telling the ring. This is
//!   the message that unblocks the protection link, and a ring that emits them
//!   repeatedly is flapping rather than converging.
//! * **No Request** with **RPL Blocked** — the steady state. The ring is
//!   healthy and the protection link is doing its job.
//! * **No Request** *without* RPL Blocked — the ring is *not* in its protected
//!   state. This is the dangerous quiet case: traffic still flows, nothing
//!   alarms, and the ring has no spare path left for the next failure.
//! * **Forced Switch** / **Manual Switch** — an operator moved the block by
//!   hand. Left in place after maintenance, it looks exactly like a healthy
//!   ring while silently having spent its protection.
//!
//! The node identifier is the sending switch's MAC address, which is what
//! turns "the ring is unstable" into "this switch is the one flapping".

use crate::models::Protocol;

use super::DissectedResult;

/// The CFM common header sits ahead of the R-APS fields.
const HEADER: usize = 4;
/// Request/state, sub-code, status, then a six-byte node identifier.
const RAPS_MINIMUM: usize = HEADER + 2 + 6;

/// The request states G.8032 defines. The gaps are deliberate; the values are
/// not consecutive.
fn request_state(state: u8) -> Option<&'static str> {
    Some(match state {
        0 => "No Request",
        7 => "Manual Switch",
        11 => "Signal Fail",
        13 => "Forced Switch",
        14 => "Event",
        _ => return None,
    })
}

/// Dissect an R-APS message.
pub fn dissect_erps(payload: &[u8]) -> DissectedResult {
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Erps,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    let Some(fields) = payload.get(HEADER..) else {
        return format!("R-APS ({})", super::bytes(payload.len() as u64));
    };
    if payload.len() < RAPS_MINIMUM {
        return format!("R-APS ({})", super::bytes(payload.len() as u64));
    }

    // The request/state is the top nibble; the low nibble is a sub-code.
    let state = fields[0] >> 4;
    let status = fields[1];
    // Version 0 on the wire is G.8032 v1; version 1 is v2. Only v2 defines the
    // blocked-port reference bit, so reading it on v1 reports a reserved bit.
    let version = payload[0] & 0x1F;

    let name = request_state(state)
        .map(str::to_string)
        .unwrap_or_else(|| format!("request state {state}"));

    // RPL Blocked is the bit that says whether the ring still has protection.
    let rpl_blocked = status & 0x80 != 0;
    let do_not_flush = status & 0x40 != 0;
    let blocked_port_ref = version >= 1 && status & 0x20 != 0;

    let node = fields
        .get(2..8)
        .map(|m| {
            format!(
                " from {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                m[0], m[1], m[2], m[3], m[4], m[5]
            )
        })
        .unwrap_or_default();

    // A "No Request" without RPL Blocked is a ring running unprotected, and it
    // is the case nothing else reports — everything works until it doesn't.
    let protection = match (state, rpl_blocked) {
        (0, true) => " — ring protected".to_string(),
        (0, false) => " — ring NOT protected, no spare path".to_string(),
        (_, true) => " — RPL blocked".to_string(),
        (_, false) => String::new(),
    };

    let mut flags = Vec::new();
    if do_not_flush {
        flags.push("do not flush");
    }
    if blocked_port_ref {
        flags.push("blocked port reference");
    }
    let flags = if flags.is_empty() {
        String::new()
    } else {
        format!(" [{}]", flags.join(", "))
    };

    format!("R-APS {name}{protection}{node}{flags}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an R-APS message.
    fn raps(version: u8, state: u8, status: u8) -> Vec<u8> {
        let mut v = vec![
            (7 << 5) | version, // ring protection runs at maintenance level 7
            super::super::cfm::OPCODE_RAPS,
            0x00, // flags
            0x20, // first TLV offset — 32 for R-APS
        ];
        v.push(state << 4);
        v.push(status);
        v.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // node id
        v.extend_from_slice(&[0u8; 24]); // reserved
        v
    }

    /// The reason this dissector exists: a signal fail is the ring rerouting,
    /// and the node identifier says which switch reported it.
    #[test]
    fn a_signal_fail_names_the_switch_that_reported_it() {
        let r = dissect_erps(&raps(1, 11, 0x00));
        assert_eq!(r.protocol, Protocol::Erps);
        assert_eq!(r.summary, "R-APS Signal Fail from 00:11:22:33:44:55");
    }

    /// The quiet failure: the ring works, nothing alarms, and there is no
    /// spare path left for the next break.
    #[test]
    fn a_ring_running_without_its_block_is_called_out() {
        let protected = describe(&raps(1, 0, 0x80));
        let exposed = describe(&raps(1, 0, 0x00));
        assert!(protected.contains("ring protected"), "{protected}");
        assert!(
            exposed.contains("NOT protected, no spare path"),
            "{exposed}"
        );
        assert_ne!(protected, exposed);
    }

    /// An operator's switch left in place looks like a healthy ring, so the
    /// states have to be told apart.
    #[test]
    fn the_operator_states_are_distinguished() {
        assert!(describe(&raps(1, 13, 0x80)).contains("Forced Switch"));
        assert!(describe(&raps(1, 7, 0x80)).contains("Manual Switch"));
        assert!(describe(&raps(1, 14, 0x00)).contains("Event"));
    }

    /// The request state is the top nibble; the low nibble is a sub-code.
    /// Reading the whole byte turns every state into an unknown one.
    #[test]
    fn the_state_is_the_top_nibble() {
        let mut with_subcode = raps(1, 11, 0x00);
        with_subcode[4] |= 0x0F; // set every sub-code bit
        assert!(describe(&with_subcode).contains("Signal Fail"));
    }

    /// The blocked-port reference bit exists only in v2. On a v1 message that
    /// bit is reserved, and reporting it would invent a field.
    #[test]
    fn the_v2_only_bit_is_not_read_on_v1() {
        let v2 = describe(&raps(1, 11, 0x20));
        let v1 = describe(&raps(0, 11, 0x20));
        assert!(v2.contains("blocked port reference"), "{v2}");
        assert!(!v1.contains("blocked port reference"), "{v1}");
    }

    #[test]
    fn the_do_not_flush_bit_is_reported() {
        assert!(describe(&raps(1, 11, 0x40)).contains("do not flush"));
    }

    /// The values are not consecutive — 0, 7, 11, 13, 14 — so an unknown one
    /// keeps its number rather than being guessed at.
    #[test]
    fn an_unassigned_state_reports_its_number() {
        assert!(describe(&raps(1, 5, 0x00)).contains("request state 5"));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "R-APS (0 bytes)");
        assert_eq!(describe(&[0xE1, 0x28]), "R-APS (2 bytes)");
        // A header with the state byte but no node identifier.
        assert_eq!(
            describe(&[0xE1, 0x28, 0, 0x20, 0xB0, 0x80]),
            "R-APS (6 bytes)"
        );
    }
}
