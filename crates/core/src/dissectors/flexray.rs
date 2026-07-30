// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! FlexRay — the bus where being on time is the protocol.
//!
//! CAN decides who talks by arbitration: the lowest identifier wins, whenever
//! it wants. FlexRay decides in advance. The cycle is divided into slots, each
//! slot belongs to one ECU, and that ECU transmits in its slot or not at all.
//! Brake-by-wire and steer-by-wire are built on it because the schedule makes
//! latency a fixed, provable number rather than a statistical one.
//!
//! That design changes what a failure looks like, and it is why this dissector
//! reports what it does.
//!
//! ## The null frame is the silent failure
//!
//! An ECU that stops producing data does **not** stop transmitting. It sends a
//! *null frame* in its slot: correct timing, correct identifier, no payload.
//! The schedule is unchanged, the bus load is unchanged, every timing
//! measurement still passes — and a control loop somewhere upstream is now
//! running on stale values. Nothing but the null-frame bit distinguishes it
//! from a healthy bus.
//!
//! **The bit is active low.** `NFI` *set* means a normal frame; `NFI` *clear*
//! means the frame is null. Reading it the intuitive way inverts the diagnosis
//! completely: every healthy frame is reported as an ECU that has stopped, and
//! the one ECU that actually stopped is reported as healthy.
//!
//! ## Startup and sync
//!
//! Only a handful of nodes in a cluster are permitted to be sync nodes, and
//! only those may set the startup indicator. A cluster that will not come up is
//! usually a question about these two bits — either too few nodes are sending
//! them, or a node is claiming a role it was not configured for.
//!
//! ## Error flags
//!
//! The capture format carries the controller's own error flags ahead of the
//! frame. A coding error or a TSS violation is the physical layer failing —
//! termination, a wiring fault, a failing transceiver — not a software problem,
//! which is worth separating before anyone reads any application data.

use crate::models::Protocol;

use super::DissectedResult;

/// Channel and type index, then the controller's error flags.
const MEASUREMENT_HEADER: usize = 2;
/// Flags and identifier, payload length, header CRC, cycle counter.
const FRAME_HEADER: usize = 5;

const TYPE_FRAME: u8 = 0x01;
const TYPE_SYMBOL: u8 = 0x02;

/// The controller's error flags, in the byte ahead of the frame.
const ERRORS: [(u8, &str); 5] = [
    (0x10, "frame CRC"),
    (0x08, "header CRC"),
    (0x04, "frame end sequence"),
    (0x02, "coding"),
    (0x01, "TSS violation"),
];

/// Dissect a FlexRay frame from a capture (DLT 210).
pub fn dissect_flexray(data: &[u8]) -> DissectedResult {
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Flexray,
        summary: describe(data),
    }
}

fn describe(data: &[u8]) -> String {
    let Some(&head) = data.first() else {
        return "FlexRay (0 bytes)".to_string();
    };
    // The channel is the top bit; the type index is the rest.
    let channel = if head & 0x80 != 0 { "B" } else { "A" };
    let kind = head & 0x7F;

    if kind == TYPE_SYMBOL {
        return match data.get(1) {
            Some(length) => format!("FlexRay symbol on channel {channel} (length {length})"),
            None => format!("FlexRay symbol on channel {channel}"),
        };
    }
    if kind != TYPE_FRAME {
        return format!("FlexRay type {kind:#04x} on channel {channel}");
    }

    // The controller's error flags come before the frame. A physical-layer
    // fault makes everything after it untrustworthy, so it is reported first
    // and the frame's own fields are not presented as fact.
    let errors: Vec<&str> = data
        .get(1)
        .map(|flags| {
            ERRORS
                .iter()
                .filter(|(mask, _)| flags & mask != 0)
                .map(|(_, name)| *name)
                .collect()
        })
        .unwrap_or_default();

    let Some(frame) = data.get(MEASUREMENT_HEADER..MEASUREMENT_HEADER + FRAME_HEADER) else {
        return format!(
            "FlexRay frame on channel {channel} ({})",
            super::bytes(data.len() as u64)
        );
    };

    if !errors.is_empty() {
        return format!(
            "FlexRay channel {channel} — {} error, the frame cannot be trusted",
            errors.join(", ")
        );
    }

    // The identifier is eleven bits spanning the first two bytes; the flags
    // occupy the rest of the first one.
    let id = u16::from_be_bytes([frame[0], frame[1]]) & 0x07FF;
    // The length is in two-byte words, so the byte count is twice it.
    let words = (frame[2] & 0xFE) >> 1;
    let cycle = frame[4] & 0x3F;

    // Active low: set means a normal frame, clear means a null one.
    let null_frame = frame[0] & 0x20 == 0;
    let sync = frame[0] & 0x10 != 0;
    let startup = frame[0] & 0x08 != 0;

    let mut roles = Vec::new();
    if sync {
        roles.push("sync");
    }
    if startup {
        roles.push("startup");
    }
    let roles = if roles.is_empty() {
        String::new()
    } else {
        format!(" [{}]", roles.join(", "))
    };

    if null_frame {
        // The slot is used, the timing is right, and there is no data in it.
        return format!(
            "FlexRay NULL FRAME — slot {id} produced nothing, channel {channel}, \
cycle {cycle}{roles}"
        );
    }

    format!(
        "FlexRay slot {id} on channel {channel}, cycle {cycle}, {}{roles}",
        super::bytes(u64::from(words) * 2)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a FlexRay frame as it appears in a capture.
    fn frame(id: u16, cycle: u8, words: u8, flags: u8, errors: u8) -> Vec<u8> {
        let mut v = vec![TYPE_FRAME, errors];
        let id_bytes = (id & 0x07FF).to_be_bytes();
        v.push(flags | id_bytes[0]);
        v.push(id_bytes[1]);
        v.push(words << 1);
        v.push(0x00); // header CRC
        v.push(cycle & 0x3F);
        v.extend_from_slice(&vec![0u8; words as usize * 2]);
        v
    }

    /// A normal frame has the null-frame indicator **set**.
    const NORMAL: u8 = 0x20;

    /// The reason this dissector exists: an ECU that has stopped producing
    /// still transmits, on time, with the right identifier and no data.
    #[test]
    fn a_null_frame_is_reported_as_an_ecu_that_stopped_producing() {
        let r = dissect_flexray(&frame(42, 7, 4, 0x00, 0x00));
        assert_eq!(r.protocol, Protocol::Flexray);
        assert_eq!(
            r.summary,
            "FlexRay NULL FRAME — slot 42 produced nothing, channel A, cycle 7"
        );
    }

    /// The indicator is active low. Reading it the intuitive way inverts every
    /// diagnosis on the bus: healthy frames become stopped ECUs and the one
    /// stopped ECU becomes healthy.
    #[test]
    fn the_null_frame_indicator_is_active_low() {
        let normal = describe(&frame(42, 7, 4, NORMAL, 0x00));
        let null = describe(&frame(42, 7, 4, 0x00, 0x00));
        assert!(!normal.contains("NULL"), "{normal}");
        assert!(null.contains("NULL FRAME"), "{null}");
        assert!(normal.contains("slot 42"), "{normal}");
    }

    /// A cluster that will not start is usually a question about these bits.
    #[test]
    fn the_sync_and_startup_roles_are_reported() {
        assert!(describe(&frame(1, 0, 2, NORMAL | 0x10, 0)).contains("[sync]"));
        assert!(describe(&frame(1, 0, 2, NORMAL | 0x08, 0)).contains("[startup]"));
        assert!(describe(&frame(1, 0, 2, NORMAL | 0x18, 0)).contains("[sync, startup]"));
    }

    /// A physical-layer fault makes the rest of the frame meaningless, so it
    /// is said plainly rather than decoded around.
    #[test]
    fn a_controller_error_is_reported_instead_of_the_fields() {
        let summary = describe(&frame(42, 7, 4, NORMAL, 0x02));
        assert!(summary.contains("coding error"), "{summary}");
        assert!(summary.contains("cannot be trusted"), "{summary}");
        assert!(!summary.contains("slot 42"), "{summary}");
    }

    #[test]
    fn every_error_flag_is_named() {
        for (mask, name) in ERRORS {
            let summary = describe(&frame(1, 0, 2, NORMAL, mask));
            assert!(summary.contains(name), "{mask:#04x}: {summary}");
        }
    }

    /// The identifier is eleven bits sharing its first byte with the flags.
    /// Reading a whole byte would fold the flags into the slot number.
    #[test]
    fn the_identifier_is_eleven_bits() {
        // The largest identifier, with every flag set alongside it.
        let summary = describe(&frame(0x07FF, 0, 2, NORMAL | 0x18, 0));
        assert!(summary.contains("slot 2047"), "{summary}");
        // A flag set must not change the slot number.
        let plain = describe(&frame(5, 0, 2, NORMAL, 0));
        let flagged = describe(&frame(5, 0, 2, NORMAL | 0x18, 0));
        assert!(plain.contains("slot 5") && flagged.contains("slot 5"));
    }

    /// The payload length counts two-byte words, not bytes.
    #[test]
    fn the_length_is_counted_in_words() {
        let summary = describe(&frame(1, 0, 8, NORMAL, 0));
        assert!(summary.contains("16 bytes"), "{summary}");
    }

    /// The cycle counter is six bits and wraps at 64.
    #[test]
    fn the_cycle_counter_is_six_bits() {
        assert!(describe(&frame(1, 63, 2, NORMAL, 0)).contains("cycle 63"));
        assert!(describe(&frame(1, 0, 2, NORMAL, 0)).contains("cycle 0"));
    }

    #[test]
    fn the_channel_is_reported() {
        let mut b = frame(1, 0, 2, NORMAL, 0);
        b[0] |= 0x80;
        assert!(describe(&b).contains("channel B"));
        assert!(describe(&frame(1, 0, 2, NORMAL, 0)).contains("channel A"));
    }

    #[test]
    fn a_symbol_is_not_read_as_a_frame() {
        let summary = describe(&[TYPE_SYMBOL, 30]);
        assert!(summary.contains("symbol"), "{summary}");
        assert!(!summary.contains("slot"), "{summary}");
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "FlexRay (0 bytes)");
        assert_eq!(
            describe(&[TYPE_FRAME, 0x00, 0x20]),
            "FlexRay frame on channel A (3 bytes)"
        );
        assert!(describe(&[TYPE_SYMBOL]).contains("symbol"));
        assert!(describe(&[0x7F, 0, 0, 0, 0, 0, 0]).contains("type 0x7f"));
    }
}
