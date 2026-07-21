// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! eCPRI — the fronthaul between a radio and its baseband (EtherType 0xAEFE).
//!
//! A modern base station is split in two: the radio unit at the top of the
//! mast, and the baseband unit at the bottom or in a datacentre. eCPRI is the
//! link between them, and it carries the sampled radio waveform itself.
//!
//! That makes it the most timing-sensitive traffic on any network that carries
//! it. The radio has to transmit on an exact symbol boundary, so IQ data that
//! arrives late is not delayed — it is *useless*, and the radio drops it. The
//! result is degraded coverage or dropped calls, while every switch on the
//! path reports healthy links and no discards.
//!
//! The Event Indication message is where the radio says so. Its fault codes
//! name the exact failure: data that arrived too early, too late, or that
//! overran or starved the playout buffer. Those four answers separate a
//! fronthaul timing problem from a radio hardware fault, and nothing else in
//! the capture distinguishes them.

use crate::models::Protocol;

use super::DissectedResult;

/// Common header: revision and C-bit, message type, payload size.
const HEADER_LEN: usize = 4;
/// Event Indication's fixed part, ahead of the fault list.
const EVENT_HEADER_LEN: usize = 4;
/// Each fault or notification element.
const ELEMENT_LEN: usize = 8;

const MSG_EVENT_INDICATION: u8 = 7;

fn message_name(message: u8) -> &'static str {
    match message {
        0 => "IQ data",
        1 => "bit sequence",
        2 => "real-time control",
        3 => "generic data transfer",
        4 => "remote memory access",
        5 => "one-way delay measurement",
        6 => "remote reset",
        MSG_EVENT_INDICATION => "event indication",
        8 => "IWF start-up",
        9 => "IWF operation",
        10 => "IWF mapping",
        11 => "IWF delay control",
        12..=63 => "reserved",
        _ => "vendor specific",
    }
}

/// What kind of event is being reported.
fn event_type(kind: u8) -> &'static str {
    match kind {
        0 => "fault",
        1 => "fault acknowledge",
        2 => "notification",
        3 => "sync request",
        4 => "sync acknowledge",
        5 => "sync end",
        _ => "reserved",
    }
}

/// The fault and notification codes. The two ranges are separate namespaces:
/// below 0x400 is a fault the radio is raising, 0x400-0x7FF a notification
/// about the data it is being sent.
fn fault_name(code: u16) -> Option<&'static str> {
    Some(match code {
        0x000 => "general userplane hardware fault",
        0x001 => "general userplane software fault",
        0x400 => "unknown message type received",
        0x401 => "userplane data buffer underflow",
        0x402 => "userplane data buffer overflow",
        0x403 => "userplane data arrived too early",
        0x404 => "userplane data received too late",
        _ => return None,
    })
}

/// Whether a code is a vendor's own rather than one the standard defines.
fn is_vendor(code: u16) -> bool {
    (0x800..=0xFFF).contains(&code)
}

/// Dissect an eCPRI message.
pub fn dissect_ecpri(payload: &[u8]) -> DissectedResult {
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Ecpri,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    let Some(head) = payload.get(..HEADER_LEN) else {
        return "eCPRI (truncated)".to_string();
    };
    let message = head[1];
    let name = message_name(message);

    if message != MSG_EVENT_INDICATION {
        return format!("eCPRI {name}");
    }

    // The payload size bounds the fault list; the frame is padded to the
    // Ethernet minimum, so trusting its length would read padding as faults.
    let size = u16::from_be_bytes([head[2], head[3]]) as usize;
    let body = payload
        .get(HEADER_LEN..HEADER_LEN + size)
        .unwrap_or(payload.get(HEADER_LEN..).unwrap_or(&[]));

    let Some(event) = body.get(..EVENT_HEADER_LEN) else {
        return format!("eCPRI {name}");
    };
    let kind = event_type(event[1]);
    let count = event[3] as usize;

    // The first fault is the news; a radio raising several at once is raising
    // them about the same underlying problem.
    let first = body
        .get(EVENT_HEADER_LEN..)
        .and_then(|list| list.get(..ELEMENT_LEN))
        .map(|element| {
            let raise = element[2] >> 4;
            let code = u16::from_be_bytes([element[2], element[3]]) & 0x0FFF;
            let what = match fault_name(code) {
                Some(text) => text.to_string(),
                None if is_vendor(code) => format!("vendor-specific {code:#05x}"),
                // A code the standard has not assigned keeps its number
                // rather than being mapped to whichever entry was nearest.
                None => format!("code {code:#05x}"),
            };
            // Ceasing a fault is how a radio says the problem went away, and
            // reads identically to raising one apart from this nibble.
            if raise == 1 {
                format!("{what} — cleared")
            } else {
                what
            }
        });

    match (first, count) {
        (Some(what), n) if n > 1 => format!("eCPRI {kind} — {what} (+{} more)", n - 1),
        (Some(what), _) => format!("eCPRI {kind} — {what}"),
        (None, _) => format!("eCPRI {kind}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an eCPRI Event Indication carrying the given fault codes.
    fn event(kind: u8, codes: &[(u16, u8)]) -> Vec<u8> {
        let mut body = vec![0x01, kind, 0x00, codes.len() as u8];
        for &(code, raise) in codes {
            body.extend_from_slice(&0xFFFFu16.to_be_bytes());
            body.extend_from_slice(&(((raise as u16) << 12) | code).to_be_bytes());
            body.extend_from_slice(&0u32.to_be_bytes());
        }
        let mut p = vec![0x10, MSG_EVENT_INDICATION];
        p.extend_from_slice(&(body.len() as u16).to_be_bytes());
        p.extend_from_slice(&body);
        p
    }

    /// The reason this dissector exists: late fronthaul data is dropped by the
    /// radio, and every switch on the path still looks healthy.
    #[test]
    fn late_userplane_data_is_spelled_out() {
        let r = dissect_ecpri(&event(0, &[(0x404, 0)]));
        assert_eq!(r.protocol, Protocol::Ecpri);
        assert_eq!(r.summary, "eCPRI fault — userplane data received too late");
    }

    /// The four timing answers separate a fronthaul problem from a radio one,
    /// and from each other.
    #[test]
    fn the_timing_faults_are_distinguished() {
        assert!(describe(&event(0, &[(0x403, 0)])).contains("too early"));
        assert!(describe(&event(0, &[(0x401, 0)])).contains("underflow"));
        assert!(describe(&event(0, &[(0x402, 0)])).contains("overflow"));
        assert!(describe(&event(0, &[(0x000, 0)])).contains("hardware fault"));
    }

    /// A cleared fault reads identically to a raised one apart from one
    /// nibble, and means the opposite.
    #[test]
    fn clearing_a_fault_is_not_raising_one() {
        let raised = describe(&event(0, &[(0x404, 0)]));
        let cleared = describe(&event(0, &[(0x404, 1)]));
        assert!(!raised.contains("cleared"), "{raised}");
        assert!(cleared.contains("cleared"), "{cleared}");
    }

    /// A code outside the standard keeps its number instead of being mapped to
    /// the nearest entry that happens to exist.
    #[test]
    fn an_unassigned_code_keeps_its_number() {
        assert!(describe(&event(0, &[(0x123, 0)])).contains("code 0x123"));
        assert!(describe(&event(0, &[(0x850, 0)])).contains("vendor-specific 0x850"));
    }

    /// Several faults at once are one problem, so the first is reported with a
    /// count rather than all of them.
    #[test]
    fn multiple_faults_report_the_first_and_a_count() {
        let summary = describe(&event(0, &[(0x404, 0), (0x401, 0), (0x402, 0)]));
        assert_eq!(
            summary,
            "eCPRI fault — userplane data received too late (+2 more)"
        );
    }

    #[test]
    fn the_other_message_types_are_named() {
        let iq = [0x10, 0x00, 0x00, 0x00];
        assert_eq!(describe(&iq), "eCPRI IQ data");
        let delay = [0x10, 0x05, 0x00, 0x00];
        assert_eq!(describe(&delay), "eCPRI one-way delay measurement");
        let vendor = [0x10, 0x80, 0x00, 0x00];
        assert_eq!(describe(&vendor), "eCPRI vendor specific");
    }

    /// The payload size bounds the fault list. Frames are padded to the
    /// Ethernet minimum, so reading to the end would decode padding as faults.
    #[test]
    fn the_payload_size_bounds_the_fault_list() {
        let mut padded = event(0, &[(0x404, 0)]);
        padded.extend_from_slice(&[0u8; 20]);
        assert_eq!(
            describe(&padded),
            "eCPRI fault — userplane data received too late"
        );
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "eCPRI (truncated)");
        assert_eq!(describe(&[0x10, 0x07, 0x00]), "eCPRI (truncated)");
        // Event indication with no room for its own header.
        assert_eq!(
            describe(&[0x10, MSG_EVENT_INDICATION, 0x00, 0x00]),
            "eCPRI event indication"
        );
        // A count promising faults the frame does not carry.
        assert_eq!(
            describe(&[
                0x10,
                MSG_EVENT_INDICATION,
                0x00,
                0x04,
                0x01,
                0x00,
                0x00,
                0x09
            ]),
            "eCPRI fault"
        );
    }
}
