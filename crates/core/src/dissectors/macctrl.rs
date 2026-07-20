// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Ethernet flow control — the PAUSE frame and its per-priority successor
//! (IEEE 802.3 Annex 31B and 802.1Qbb).
//!
//! A PAUSE frame is a switch or a network card telling the far end to stop
//! transmitting for a while because its buffers are filling. That makes it one
//! of the most diagnostically valuable frames on a link: a burst of them
//! explains slowness that looks inexplicable from the application's side, since
//! nothing is lost and nothing is retransmitted — traffic is simply being held.
//!
//! The quantum is expressed in units of 512 bit-times, so what it means in real
//! time depends on the link speed, which is worth stating rather than printing
//! a bare number.

use crate::models::Protocol;

use super::DissectedResult;

/// Opcode, then the parameters.
const HEADER: usize = 2;
const OPCODE_PAUSE: u16 = 0x0001;
const OPCODE_PFC: u16 = 0x0101;

/// One quantum is 512 bit-times, so its duration depends on the link rate.
fn pause_duration(quanta: u16) -> String {
    if quanta == 0 {
        // Zero is an explicit "resume now", not a zero-length pause.
        return "resume".to_string();
    }
    let bit_times = quanta as u64 * 512;
    // Quote the two rates a reader is most likely to be on.
    let micros_at_1g = bit_times / 1_000;
    let micros_at_10g = bit_times / 10_000;
    format!("{quanta} quanta (~{micros_at_1g}µs at 1G, ~{micros_at_10g}µs at 10G)")
}

/// Dissect an Ethernet flow-control frame (EtherType 0x8808).
pub fn dissect_mac_control(payload: &[u8]) -> DissectedResult {
    let result = |summary: String| DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::MacControl,
        summary,
    };
    if payload.len() < HEADER {
        return result(format!(
            "MAC control ({})",
            super::bytes(payload.len() as u64)
        ));
    }
    let opcode = u16::from_be_bytes([payload[0], payload[1]]);
    match opcode {
        OPCODE_PAUSE => match payload.get(2..4) {
            Some(q) => {
                let quanta = u16::from_be_bytes([q[0], q[1]]);
                result(format!("Ethernet PAUSE — {}", pause_duration(quanta)))
            }
            None => result("Ethernet PAUSE".to_string()),
        },
        // Priority flow control pauses individual traffic classes rather than
        // the whole link, so which classes are affected is the useful part.
        OPCODE_PFC => match payload.get(2..4) {
            Some(v) => {
                let enabled = u16::from_be_bytes([v[0], v[1]]) & 0x00FF;
                let classes: Vec<String> = (0..8)
                    .filter(|c| enabled & (1 << c) != 0)
                    .map(|c| c.to_string())
                    .collect();
                if classes.is_empty() {
                    result("Priority flow control — no classes paused".to_string())
                } else {
                    result(format!(
                        "Priority flow control — pausing class{} {}",
                        if classes.len() == 1 { "" } else { "es" },
                        classes.join(", ")
                    ))
                }
            }
            None => result("Priority flow control".to_string()),
        },
        other => result(format!("MAC control opcode 0x{other:04x}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pause(quanta: u16) -> Vec<u8> {
        let mut p = OPCODE_PAUSE.to_be_bytes().to_vec();
        p.extend_from_slice(&quanta.to_be_bytes());
        p
    }

    /// A burst of these explains slowness that looks inexplicable from the
    /// application's side: nothing is lost, traffic is just being held.
    #[test]
    fn a_pause_reports_how_long_it_holds_traffic() {
        let r = dissect_mac_control(&pause(0xFFFF));
        assert_eq!(r.protocol, Protocol::MacControl);
        assert_eq!(
            r.summary,
            "Ethernet PAUSE — 65535 quanta (~33553µs at 1G, ~3355µs at 10G)"
        );
    }

    /// Zero quanta is an explicit instruction to resume, not a pause of no
    /// length — reporting it as "0 quanta" would invert the meaning.
    #[test]
    fn zero_quanta_means_resume() {
        let r = dissect_mac_control(&pause(0));
        assert_eq!(r.summary, "Ethernet PAUSE — resume");
    }

    /// Priority flow control stops individual traffic classes, which is what
    /// makes it usable on a converged link where storage and general traffic
    /// share the wire.
    #[test]
    fn priority_flow_control_names_the_paused_classes() {
        let mut p = OPCODE_PFC.to_be_bytes().to_vec();
        p.extend_from_slice(&0b0000_1001u16.to_be_bytes()); // classes 0 and 3
        p.extend_from_slice(&[0u8; 16]);
        let r = dissect_mac_control(&p);
        assert_eq!(r.summary, "Priority flow control — pausing classes 0, 3");
    }

    #[test]
    fn a_single_paused_class_reads_naturally() {
        let mut p = OPCODE_PFC.to_be_bytes().to_vec();
        p.extend_from_slice(&0b0000_0010u16.to_be_bytes());
        let r = dissect_mac_control(&p);
        assert_eq!(r.summary, "Priority flow control — pausing class 1");
    }

    #[test]
    fn an_empty_class_vector_is_reported() {
        let mut p = OPCODE_PFC.to_be_bytes().to_vec();
        p.extend_from_slice(&0u16.to_be_bytes());
        let r = dissect_mac_control(&p);
        assert_eq!(r.summary, "Priority flow control — no classes paused");
    }

    #[test]
    fn unknown_opcode_and_truncation_do_not_panic() {
        let r = dissect_mac_control(&[0x9A, 0xBC]);
        assert_eq!(r.summary, "MAC control opcode 0x9abc");
        let r = dissect_mac_control(&[0x00]);
        assert_eq!(r.summary, "MAC control (1 byte)");
    }
}
