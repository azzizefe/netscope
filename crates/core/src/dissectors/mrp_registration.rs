// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! MVRP and MMRP — switches agreeing which VLANs and groups go where (802.1ak).
//!
//! A switch does not need to carry a VLAN that nothing downstream is using.
//! These two protocols are how the ports tell each other what they want: MVRP
//! registers VLANs, MMRP registers multicast groups and MAC addresses. Both use
//! the same attribute encoding, which is why they share a dissector.
//!
//! Worth reading because the symptom of getting this wrong is asymmetric and
//! confusing: traffic works in one direction, or works until a link flaps and
//! then does not. A capture showing a `Leave` for a VLAN that should be there
//! explains it immediately.
//!
//! The encoding is compact and easy to misread. Attributes are grouped by type,
//! each group carries a list of events, and the events are packed **three to a
//! byte in base 6** — not one per byte, and not two per nibble.

use crate::models::Protocol;

use super::DissectedResult;

/// What a registration event asks for. These are the "applicant" states in the
/// standard's terms, but the useful reading is simply what happens next.
fn event_name(event: u8) -> Option<&'static str> {
    Some(match event {
        0 => "New",
        1 => "JoinIn",
        2 => "In",
        3 => "JoinEmpty",
        4 => "Empty",
        5 => "Leave",
        _ => return None,
    })
}

/// Which attribute a group is registering.
fn attribute_name(protocol: &Protocol, attribute: u8) -> &'static str {
    match (protocol, attribute) {
        (&Protocol::Mvrp, 1) => "VLAN",
        (&Protocol::Mmrp, 1) => "service requirement",
        (&Protocol::Mmrp, 2) => "MAC address",
        _ => "attribute",
    }
}

/// Unpack the three events packed into one byte.
///
/// The standard stores them as a base-6 number, most significant first, so the
/// first event is the *quotient* by 36 and not the low bits. Reading them as
/// bytes or nibbles produces plausible-looking values that are wrong.
fn unpack_events(packed: u8) -> [u8; 3] {
    [packed / 36, (packed / 6) % 6, packed % 6]
}

/// Dissect an MVRP or MMRP frame.
pub fn dissect(payload: &[u8], protocol: Protocol) -> DissectedResult {
    let summary = describe(payload, &protocol);
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol,
        summary,
    }
}

fn describe(payload: &[u8], protocol: &Protocol) -> String {
    let label = if protocol == &Protocol::Mvrp {
        "MVRP"
    } else {
        "MMRP"
    };
    // Protocol version, then the first message: attribute type and length.
    let Some(&attribute) = payload.get(1) else {
        return format!("{label} frame");
    };
    let what = attribute_name(protocol, attribute);

    // Attribute length, then the vector header: two bytes whose low 13 bits
    // are how many values follow the first.
    let Some(header) = payload.get(3..5) else {
        return format!("{label} — {what} registration");
    };
    let count = (u16::from_be_bytes([header[0], header[1]]) & 0x1FFF) as usize + 1;

    // The first value, then the packed events.
    let value_len = payload.get(2).copied().unwrap_or(2) as usize;
    let first_value = payload
        .get(5..5 + value_len)
        .map(|v| v.iter().fold(0u32, |a, &b| (a << 8) | b as u32));
    let event = payload
        .get(5 + value_len)
        .map(|&packed| unpack_events(packed)[0])
        .and_then(event_name);

    match (first_value, event) {
        (Some(value), Some(event)) if count > 1 => {
            format!("{label} {event} — {what} {value} (+{} more)", count - 1)
        }
        (Some(value), Some(event)) => format!("{label} {event} — {what} {value}"),
        (Some(value), None) => format!("{label} — {what} {value}"),
        _ => format!("{label} — {what} registration"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a registration frame for one attribute value.
    fn frame(attribute: u8, value: u16, count: u16, events: [u8; 3]) -> Vec<u8> {
        let mut p = vec![0x00, attribute, 0x02];
        // The vector header's low 13 bits are the number of *additional*
        // values, so a single value is encoded as zero.
        p.extend_from_slice(&(count - 1).to_be_bytes());
        p.extend_from_slice(&value.to_be_bytes());
        p.push(events[0] * 36 + events[1] * 6 + events[2]);
        p.push(0x00); // end mark
        p
    }

    /// The everyday case: a switch asking for a VLAN to be carried.
    #[test]
    fn a_vlan_registration_names_the_vlan_and_what_it_asks() {
        // JoinIn for VLAN 100.
        let p = frame(1, 100, 1, [1, 0, 0]);
        let r = dissect(&p, Protocol::Mvrp);
        assert_eq!(r.protocol, Protocol::Mvrp);
        assert_eq!(r.summary, "MVRP JoinIn — VLAN 100");
    }

    /// A Leave is what explains traffic that used to work and stopped, so it
    /// has to be distinguishable from a Join.
    #[test]
    fn a_leave_is_distinguished_from_a_join() {
        let leave = dissect(&frame(1, 100, 1, [5, 0, 0]), Protocol::Mvrp).summary;
        assert_eq!(leave, "MVRP Leave — VLAN 100");
        assert!(!leave.contains("Join"));
    }

    /// Events are packed three to a byte in base 6. Reading the byte directly,
    /// or as nibbles, gives a plausible wrong answer — `New, New, Leave` packs
    /// to 5, which read as a raw byte is `Leave`.
    #[test]
    fn events_are_unpacked_from_base_six_not_read_as_bytes() {
        assert_eq!(unpack_events(0), [0, 0, 0]);
        assert_eq!(unpack_events(5), [0, 0, 5]);
        assert_eq!(unpack_events(36), [1, 0, 0]);
        assert_eq!(unpack_events(215), [5, 5, 5]);
        // 36 is JoinIn-then-New-then-New. A raw read would call it 36, a nibble
        // read would call it 2.
        assert_eq!(
            dissect(&frame(1, 7, 1, [1, 0, 0]), Protocol::Mvrp).summary,
            "MVRP JoinIn — VLAN 7"
        );
    }

    /// One message can register a run of VLANs, and the count must not be lost.
    #[test]
    fn a_run_of_values_is_counted() {
        assert_eq!(
            dissect(&frame(1, 10, 4, [1, 1, 1]), Protocol::Mvrp).summary,
            "MVRP JoinIn — VLAN 10 (+3 more)"
        );
    }

    /// MMRP shares the encoding but registers different things, and calling an
    /// MMRP attribute a VLAN would be wrong.
    #[test]
    fn mmrp_names_its_own_attributes() {
        assert!(dissect(&frame(2, 1, 1, [1, 0, 0]), Protocol::Mmrp)
            .summary
            .contains("MAC address"));
        assert!(dissect(&frame(1, 1, 1, [1, 0, 0]), Protocol::Mmrp)
            .summary
            .contains("service requirement"));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(dissect(&[], Protocol::Mvrp).summary, "MVRP frame");
        assert_eq!(dissect(&[0x00], Protocol::Mvrp).summary, "MVRP frame");
        assert!(dissect(&[0x00, 0x01, 0x02], Protocol::Mvrp)
            .summary
            .contains("registration"));
    }
}
