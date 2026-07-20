// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Link OAM — a link reporting its own health, and its own death (802.3ah).
//!
//! Two devices at either end of a link exchange these continuously. Most of the
//! time they say nothing interesting. The value is in the exception, and there
//! are two worth knowing on sight.
//!
//! **Dying gasp** is the last thing a device sends as its power fails. A
//! modem, an ONT or a remote switch losing mains power gets one frame out
//! before it stops, and that frame is the difference between "the site went
//! down at 04:12" and "the site's power went at 04:12". Nothing else in a
//! capture distinguishes a power cut from a cut fibre.
//!
//! **Event notifications** carry error counters, so a link that is degrading
//! says so before it fails outright — errored symbols climbing over hours is a
//! transceiver or a fibre going bad while everything still nominally works.

use crate::models::Protocol;

use super::DissectedResult;

/// Flag bits in the two bytes after the subtype.
const FLAG_LINK_FAULT: u16 = 0x0001;
const FLAG_DYING_GASP: u16 = 0x0002;
const FLAG_CRITICAL_EVENT: u16 = 0x0004;

/// What the frame is for.
fn code_name(code: u8) -> Option<&'static str> {
    Some(match code {
        0x00 => "information",
        0x01 => "event notification",
        0x02 => "variable request",
        0x03 => "variable response",
        0x04 => "loopback control",
        0xFE => "organisation-specific",
        _ => return None,
    })
}

/// The kind of error an event notification is reporting.
fn event_name(event: u8) -> Option<&'static str> {
    Some(match event {
        0x01 => "errored symbol period",
        0x02 => "errored frame period",
        0x03 => "errored frame",
        0x04 => "errored frame seconds summary",
        0xFE => "organisation-specific event",
        _ => return None,
    })
}

/// Dissect an 802.3ah OAM frame. `payload` starts at the slow-protocol subtype.
pub(crate) fn describe(payload: &[u8]) -> String {
    let Some(flags) = payload.get(1..3).map(|b| u16::from_be_bytes([b[0], b[1]])) else {
        return "Ethernet OAM".to_string();
    };

    // The failure flags outrank whatever the frame was nominally carrying: a
    // dying gasp rides on an ordinary information frame, and reporting that as
    // "information" would bury the one thing that matters.
    if flags & FLAG_DYING_GASP != 0 {
        return "Ethernet OAM — dying gasp (the far end is losing power)".to_string();
    }
    if flags & FLAG_CRITICAL_EVENT != 0 {
        return "Ethernet OAM — critical event at the far end".to_string();
    }
    if flags & FLAG_LINK_FAULT != 0 {
        return "Ethernet OAM — link fault (the far end cannot receive)".to_string();
    }

    let Some(&code) = payload.get(3) else {
        return "Ethernet OAM".to_string();
    };
    let name = match code_name(code) {
        Some(n) => n,
        None => return format!("Ethernet OAM (code 0x{code:02x})"),
    };

    // An event notification names which counter tripped, which is what says
    // whether a link is degrading and how.
    if code == 0x01 {
        // Sequence number, then the first event TLV: type, length, then data.
        if let Some(&event) = payload.get(6) {
            return match event_name(event) {
                Some(what) => format!("Ethernet OAM event — {what}"),
                None => format!("Ethernet OAM event — type 0x{event:02x}"),
            };
        }
    }

    format!("Ethernet OAM — {name}")
}

/// Build the result for an OAM frame lifted out of the slow-protocol family.
pub(crate) fn result(payload: &[u8]) -> DissectedResult {
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::LinkOam,
        summary: describe(payload),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an OAM frame: subtype, flags, code, then a body.
    fn oam(flags: u16, code: u8, body: &[u8]) -> Vec<u8> {
        let mut p = vec![0x03];
        p.extend_from_slice(&flags.to_be_bytes());
        p.push(code);
        p.extend_from_slice(body);
        p
    }

    /// The single most valuable frame in the protocol: a device's last words as
    /// its power fails. Nothing else separates a power cut from a cut fibre.
    #[test]
    fn a_dying_gasp_is_reported_as_one() {
        let r = result(&oam(FLAG_DYING_GASP, 0x00, &[]));
        assert_eq!(r.protocol, Protocol::LinkOam);
        assert_eq!(
            r.summary,
            "Ethernet OAM — dying gasp (the far end is losing power)"
        );
    }

    /// A dying gasp rides on an ordinary information frame. Reading the code
    /// instead of the flags would report it as "information" and bury it.
    #[test]
    fn the_failure_flags_outrank_the_frame_code() {
        // Code 0x00 is "information"; the flag is what matters.
        let summary = describe(&oam(FLAG_DYING_GASP, 0x00, &[]));
        assert!(summary.contains("dying gasp"), "{summary}");
        assert!(!summary.contains("information"), "the flag was ignored");

        assert!(describe(&oam(FLAG_LINK_FAULT, 0x00, &[])).contains("link fault"));
        assert!(describe(&oam(FLAG_CRITICAL_EVENT, 0x00, &[])).contains("critical event"));
    }

    /// A degrading link says so before it fails, and which counter tripped is
    /// what says whether it is the fibre, the optic or the far end.
    #[test]
    fn an_event_notification_names_the_counter() {
        // Sequence number, then the event TLV type.
        let r = result(&oam(0, 0x01, &[0x00, 0x01, 0x01]));
        assert_eq!(r.summary, "Ethernet OAM event — errored symbol period");
        assert!(describe(&oam(0, 0x01, &[0x00, 0x01, 0x03])).contains("errored frame"));
    }

    /// The ordinary keepalive is the common case and should read plainly.
    #[test]
    fn a_healthy_link_reads_plainly() {
        assert_eq!(describe(&oam(0, 0x00, &[])), "Ethernet OAM — information");
        assert_eq!(
            describe(&oam(0, 0x04, &[])),
            "Ethernet OAM — loopback control"
        );
    }

    /// Codes outside the standard keep their number.
    #[test]
    fn unknown_codes_keep_their_numbers() {
        assert_eq!(describe(&oam(0, 0x42, &[])), "Ethernet OAM (code 0x42)");
        assert!(describe(&oam(0, 0x01, &[0x00, 0x01, 0x77])).contains("type 0x77"));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[0x03]), "Ethernet OAM");
        assert_eq!(describe(&[0x03, 0x00, 0x00]), "Ethernet OAM");
        assert!(describe(&oam(0, 0x01, &[])).contains("event notification"));
    }
}
