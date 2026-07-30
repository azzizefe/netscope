// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! LIN — the cheap bus behind every door mirror and seat motor (DLT 212).
//!
//! CAN is expensive per node, so carmakers put the things that only need a few
//! bytes a second on LIN instead: window motors, seat adjusters, mirrors, rain
//! sensors, interior lighting. One master polls a handful of slaves over a
//! single wire, and every frame is the master asking a specific slave to speak.
//!
//! That polling structure is why the errors matter more than the data.
//!
//! ## What the error flags say
//!
//! * **No slave response** — the master asked and nothing answered. On a bus
//!   this simple that means the device is dead, unplugged, or unpowered, and it
//!   is the single most useful line in a LIN capture.
//! * **Checksum error** — something answered but the frame was corrupt, which
//!   points at wiring rather than at the device.
//! * **Parity error** — the frame identifier itself was damaged, so even the
//!   question did not arrive intact.
//!
//! Those three separate a broken device from broken wiring from a broken
//! master, and a mechanic replacing the wrong one is the ordinary cost of not
//! being able to tell.
//!
//! Two identifiers are reserved for diagnostics — 0x3C for the master's request
//! and 0x3D for the slave's response — and they carry the same transport as
//! CAN's, so a diagnostic session on LIN reads through
//! [`super::isotp`] the same way.

use crate::models::Protocol;

use super::DissectedResult;

/// Pseudo-header: bus id (4 bytes), then length/type/checksum-type, then the
/// protected identifier.
const HEADER_LEN: usize = 6;

const PAYLOAD_LENGTH_MASK: u8 = 0xF0;
const MSG_TYPE_MASK: u8 = 0x0C;
const CHECKSUM_TYPE_MASK: u8 = 0x03;
/// The identifier is six bits; the top two are its parity.
const FRAME_ID_MASK: u8 = 0x3F;

const MSG_TYPE_FRAME: u8 = 0;
const MSG_TYPE_EVENT: u8 = 3;

/// Diagnostic frame identifiers, which carry an ISO-TP transport.
const DIAG_MASTER_REQUEST: u8 = 0x3C;
const DIAG_SLAVE_RESPONSE: u8 = 0x3D;

/// Error bits, in the trailing error word.
const ERRORS: &[(u8, &str)] = &[
    (0x01, "no slave response — nothing answered the master"),
    (0x02, "framing error"),
    (0x04, "parity error — the identifier itself was damaged"),
    (0x08, "checksum error"),
    (0x10, "invalid identifier"),
    (0x20, "overflow"),
];

/// Which checksum the frame used. Classic covers only the data; enhanced
/// includes the identifier, and a slave using the wrong one fails every frame
/// while looking electrically perfect.
fn checksum_type(value: u8) -> &'static str {
    match value {
        1 => "classic",
        2 => "enhanced",
        _ => "unspecified",
    }
}

/// Dissect a LIN frame from a capture pseudo-header.
pub fn dissect_lin(payload: &[u8]) -> DissectedResult {
    let base = DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Lin,
        summary: String::new(),
    };
    let Some(head) = payload.get(..HEADER_LEN) else {
        return DissectedResult {
            summary: "LIN (truncated)".into(),
            ..base
        };
    };

    // Length, message type and checksum type share one byte.
    let length = ((head[4] & PAYLOAD_LENGTH_MASK) >> 4) as usize;
    let msg_type = (head[4] & MSG_TYPE_MASK) >> 2;
    let checksum = head[4] & CHECKSUM_TYPE_MASK;
    let id = head[5] & FRAME_ID_MASK;

    if msg_type == MSG_TYPE_EVENT {
        return DissectedResult {
            summary: "LIN bus event (sleep or wake-up)".into(),
            ..base
        };
    }
    if msg_type != MSG_TYPE_FRAME {
        return DissectedResult {
            summary: format!("LIN (message type {msg_type})"),
            ..base
        };
    }

    let data = payload.get(HEADER_LEN..HEADER_LEN + length).unwrap_or(&[]);

    // The error word follows the data, and it is the reason to read a LIN
    // capture at all.
    let error_word = payload.get(HEADER_LEN + length).copied().unwrap_or(0);
    let faults: Vec<&str> = ERRORS
        .iter()
        .filter(|(bit, _)| error_word & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    if !faults.is_empty() {
        return DissectedResult {
            summary: format!("LIN id 0x{id:02X} — {}", faults.join(", ")),
            ..base
        };
    }

    // A diagnostic frame carries the same transport CAN uses, so a session on
    // LIN reads the same way as one on CAN.
    if matches!(id, DIAG_MASTER_REQUEST | DIAG_SLAVE_RESPONSE) && !data.is_empty() {
        let who = if id == DIAG_MASTER_REQUEST {
            "master request"
        } else {
            "slave response"
        };
        if super::isotp::looks_like_isotp(data) {
            return DissectedResult {
                summary: format!("LIN diagnostic {who} · {}", super::isotp::describe(data)),
                ..base
            };
        }
        return DissectedResult {
            summary: format!("LIN diagnostic {who}"),
            ..base
        };
    }

    let hex: Vec<String> = data.iter().map(|b| format!("{b:02X}")).collect();
    let body = if hex.is_empty() {
        String::new()
    } else {
        format!("  {}", hex.join(" "))
    };
    DissectedResult {
        summary: format!(
            "LIN id 0x{id:02X} [{length}] ({} checksum){body}",
            checksum_type(checksum)
        ),
        ..base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a LIN frame with the given identifier, data and error word.
    fn lin(id: u8, checksum: u8, data: &[u8], errors: u8) -> Vec<u8> {
        let mut v = vec![0, 0, 0, 1]; // bus id
        v.push(((data.len() as u8) << 4) | (MSG_TYPE_FRAME << 2) | checksum);
        v.push(id);
        v.extend_from_slice(data);
        v.push(errors);
        v
    }

    /// The reason this dissector exists: on a bus this simple, "nobody
    /// answered" is the whole diagnosis.
    #[test]
    fn a_missing_slave_is_the_headline() {
        let r = dissect_lin(&lin(0x11, 2, &[], 0x01));
        assert_eq!(r.protocol, Protocol::Lin);
        assert_eq!(
            r.summary,
            "LIN id 0x11 — no slave response — nothing answered the master"
        );
    }

    /// The three faults point at three different repairs, so they must be
    /// distinguishable rather than lumped into "error".
    #[test]
    fn the_faults_are_distinguished() {
        assert!(dissect_lin(&lin(0x11, 2, &[0xAA], 0x08))
            .summary
            .contains("checksum error"));
        assert!(dissect_lin(&lin(0x11, 2, &[0xAA], 0x04))
            .summary
            .contains("the identifier itself was damaged"));
        // Several at once are all reported; a bus in this state is not healthy.
        let many = dissect_lin(&lin(0x11, 2, &[0xAA], 0x0C)).summary;
        assert!(many.contains("parity"), "{many}");
        assert!(many.contains("checksum"), "{many}");
    }

    /// A healthy frame reports its data and which checksum was used — a slave
    /// using the wrong one fails every frame while looking perfect on a meter.
    #[test]
    fn a_healthy_frame_reports_its_data_and_checksum_kind() {
        let r = dissect_lin(&lin(0x22, 2, &[0xDE, 0xAD], 0));
        assert_eq!(r.summary, "LIN id 0x22 [2] (enhanced checksum)  DE AD");
        assert!(dissect_lin(&lin(0x22, 1, &[0x01], 0))
            .summary
            .contains("classic checksum"));
    }

    /// Length, message type and checksum type share one byte, so reading it
    /// whole makes every length wrong by a factor of sixteen.
    #[test]
    fn the_length_is_taken_from_its_own_nibble() {
        let r = dissect_lin(&lin(0x01, 2, &[1, 2, 3, 4], 0));
        assert!(r.summary.contains("[4]"), "{}", r.summary);
    }

    /// The identifier is six bits; the top two are parity and are not part of
    /// it, so an identifier read whole is wrong whenever parity is set.
    #[test]
    fn the_identifier_excludes_its_parity_bits() {
        // 0x11 with both parity bits set.
        let r = dissect_lin(&lin(0xC0 | 0x11, 2, &[0x01], 0));
        assert!(r.summary.contains("id 0x11"), "{}", r.summary);
    }

    /// Diagnostics on LIN use the same transport as on CAN, so a session reads
    /// the same way.
    #[test]
    fn a_diagnostic_frame_is_handed_to_the_shared_transport() {
        // Single frame, two bytes: DiagnosticSessionControl.
        let r = dissect_lin(&lin(DIAG_MASTER_REQUEST, 1, &[0x02, 0x10, 0x03], 0));
        assert!(
            r.summary.starts_with("LIN diagnostic master request · "),
            "{}",
            r.summary
        );
        assert!(r.summary.contains("UDS"), "{}", r.summary);

        let reply = dissect_lin(&lin(DIAG_SLAVE_RESPONSE, 1, &[0x02, 0x50, 0x03], 0));
        assert!(
            reply.summary.contains("slave response"),
            "{}",
            reply.summary
        );
    }

    /// A bus event is not a frame and has no identifier to report.
    #[test]
    fn a_bus_event_is_not_read_as_a_frame() {
        let mut v = vec![0, 0, 0, 1];
        v.push(MSG_TYPE_EVENT << 2);
        v.push(0);
        assert_eq!(dissect_lin(&v).summary, "LIN bus event (sleep or wake-up)");
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(dissect_lin(&[]).summary, "LIN (truncated)");
        assert_eq!(dissect_lin(&[0; 5]).summary, "LIN (truncated)");
        // A frame claiming more data than it carries.
        let mut short = vec![0, 0, 0, 1, 0x80 | (MSG_TYPE_FRAME << 2) | 2, 0x11];
        short.push(0xAA);
        assert!(dissect_lin(&short).summary.contains("id 0x11"));
    }
}
