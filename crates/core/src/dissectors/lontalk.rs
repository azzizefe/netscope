// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! LonTalk (ANSI/CEA-709.1) — the control language inside a building.
//!
//! A thermostat telling an air handler it wants more heat, a light switch
//! telling a ballast to dim, a card reader telling a door to unlock. LonWorks
//! networks have been doing this in commercial buildings since before those
//! buildings had IP, and a great many still are. Reached here through
//! [`super::cnip`], which tunnels these frames between segments.
//!
//! ## The delivery class is the diagnosis
//!
//! LonTalk lets each message choose how hard the network should try:
//!
//! * **ACKD** — acknowledged. The sender waits, and retries if nobody answers.
//! * **UnACKD_RPT** — unacknowledged but repeated, sent several times in the
//!   hope one arrives. Nothing confirms any of them did.
//! * **REMINDER** — the transport layer asking for messages it never received.
//!
//! A network turning up a lot of reminders and repeats is one where control
//! messages are being lost. The building does not obviously break: a setpoint
//! occasionally fails to take, a light occasionally does not respond. From
//! inside the control software this is invisible, because the software only
//! knows what it sent.
//!
//! ## The authentication bit
//!
//! LonTalk can authenticate a message with a challenge and reply, and the bit
//! that says whether it did sits in the transport byte. On a network where door
//! controllers and access hardware share the wire with lighting, an
//! unauthenticated command to a lock is a command anyone on the segment can
//! forge — and nothing in the building's own software will mention it.

/// Priority byte, then the network header.
const HEADER: usize = 2;

/// The PDU formats, in bits 5-4 of the network header.
fn pdu_format(format: u8) -> &'static str {
    match format {
        0 => "TPDU",
        1 => "SPDU",
        2 => "AuthPDU",
        _ => "APDU",
    }
}

/// The transport delivery classes.
fn tpdu_type(kind: u8) -> Option<&'static str> {
    Some(match kind {
        0 => "acknowledged",
        1 => "unacknowledged, repeated",
        2 => "acknowledgement",
        4 => "REMINDER — asking for messages it never received",
        5 => "reminder with message",
        _ => return None,
    })
}

/// The session classes.
fn spdu_type(kind: u8) -> Option<&'static str> {
    Some(match kind {
        0 => "request",
        2 => "response",
        4 => "REMINDER — asking for messages it never received",
        5 => "reminder with message",
        _ => return None,
    })
}

/// The authentication exchange.
fn authpdu_type(kind: u8) -> Option<&'static str> {
    Some(match kind {
        0 => "challenge",
        2 => "reply",
        _ => return None,
    })
}

fn address_format(format: u8) -> &'static str {
    match format {
        0 => "broadcast",
        1 => "multicast",
        2 => "unicast or multicast",
        _ => "unicast",
    }
}

/// Describe a LonTalk frame.
///
/// There is no standalone entry point: LonTalk is only ever reached inside a
/// [`super::cnip`] tunnel, and a dissector nothing calls is worse than none.
pub(crate) fn describe(payload: &[u8]) -> String {
    let Some(head) = payload.get(..HEADER) else {
        return format!("LonTalk ({})", super::bytes(payload.len() as u64));
    };
    // The network header packs four fields into one byte.
    let network = head[1];
    let format = (network >> 4) & 0x03;
    let addressing = (network >> 2) & 0x03;

    let name = pdu_format(format);
    let addressing = address_format(addressing);

    // The transport byte follows the address and domain, whose lengths depend
    // on the addressing mode — so it is only read when it is actually there.
    // Broadcast, multicast and unicast all use three address bytes.
    let Some(&transport) = payload.get(HEADER + 3) else {
        return format!("LonTalk {name} ({addressing})");
    };

    // The class occupies bits 6-4; the top bit says whether it is authenticated.
    let authenticated = transport & 0x80 != 0;
    let class = (transport >> 4) & 0x07;

    let described = match format {
        0 => tpdu_type(class),
        1 => spdu_type(class),
        2 => authpdu_type(class),
        _ => None,
    };

    let class = described
        .map(str::to_string)
        .unwrap_or_else(|| format!("class {class}"));

    // On a wire shared with door controllers, whether a command was
    // authenticated is the difference between a command and a suggestion.
    let auth = if authenticated { ", authenticated" } else { "" };

    format!("LonTalk {name} {class} ({addressing}{auth})")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a LonTalk frame.
    fn lon(format: u8, addressing: u8, class: u8, authenticated: bool) -> Vec<u8> {
        vec![
            0x00,                              // priority byte
            (format << 4) | (addressing << 2), // network header
            0x01,                              // source subnet
            0x02,                              // source node
            0x03,                              // destination
            if authenticated { 0x80 } else { 0x00 } | (class << 4),
        ]
    }

    /// The reason this dissector exists: a network full of reminders is one
    /// losing control messages, and the building only fails intermittently.
    #[test]
    fn a_reminder_is_reported_as_missing_messages() {
        assert_eq!(
            describe(&lon(0, 0, 4, false)),
            "LonTalk TPDU REMINDER — asking for messages it never received (broadcast)"
        );
    }

    /// Acknowledged and repeated are different promises about delivery.
    #[test]
    fn the_delivery_classes_are_distinguished() {
        assert!(describe(&lon(0, 3, 0, false)).contains("acknowledged"));
        assert!(describe(&lon(0, 3, 1, false)).contains("unacknowledged, repeated"));
        assert!(describe(&lon(0, 3, 2, false)).contains("acknowledgement"));
    }

    /// On a wire shared with door hardware, an unauthenticated command is one
    /// anyone on the segment can forge.
    #[test]
    fn the_authentication_bit_is_reported() {
        let signed = describe(&lon(0, 3, 0, true));
        let plain = describe(&lon(0, 3, 0, false));
        assert!(signed.contains("authenticated"), "{signed}");
        assert!(!plain.contains("authenticated"), "{plain}");
    }

    /// The same class number means different things in each PDU format, so the
    /// format decides which table is read.
    #[test]
    fn the_format_selects_the_class_table() {
        // Class 0 is `acknowledged` in a TPDU, `request` in an SPDU and
        // `challenge` in an AuthPDU.
        assert!(describe(&lon(0, 3, 0, false)).contains("acknowledged"));
        assert!(describe(&lon(1, 3, 0, false)).contains("request"));
        assert!(describe(&lon(2, 3, 0, false)).contains("challenge"));
        // Class 2 is `acknowledgement`, `response` and `reply`.
        assert!(describe(&lon(1, 3, 2, false)).contains("response"));
        assert!(describe(&lon(2, 3, 2, false)).contains("reply"));
    }

    /// The network header packs the format, addressing and domain length into
    /// one byte. Reading it whole loses all three.
    #[test]
    fn the_network_header_is_packed_into_one_byte() {
        // Every neighbouring bit set, with the format still readable.
        let mut frame = lon(2, 3, 0, false);
        frame[1] |= 0xC3; // version bits and domain length
        let summary = describe(&frame);
        assert!(summary.contains("AuthPDU"), "{summary}");
        assert!(summary.contains("unicast"), "{summary}");
    }

    #[test]
    fn the_addressing_modes_are_named() {
        assert!(describe(&lon(0, 0, 0, false)).contains("broadcast"));
        assert!(describe(&lon(0, 1, 0, false)).contains("multicast"));
        assert!(describe(&lon(0, 3, 0, false)).contains("unicast"));
    }

    #[test]
    fn an_unassigned_class_reports_its_number() {
        assert!(describe(&lon(0, 3, 6, false)).contains("class 6"));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "LonTalk (0 bytes)");
        assert_eq!(describe(&[0x00]), "LonTalk (1 byte)");
        // A header with no transport byte reports only what it has.
        assert_eq!(
            describe(&[0x00, 0x00, 0x01, 0x02, 0x03]),
            "LonTalk TPDU (broadcast)"
        );
    }
}
