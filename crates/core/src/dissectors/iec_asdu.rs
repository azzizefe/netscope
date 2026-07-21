// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! The IEC 60870-5 ASDU — what a telecontrol message actually says.
//!
//! IEC 60870-5 is the protocol behind a great deal of electricity
//! transmission: substations reporting breaker positions and busbar voltages,
//! control centres sending the commands that open and close those breakers.
//!
//! The transport differs by variant — **-104** runs over TCP, **-101** over a
//! serial line — but the message inside is the same Application Service Data
//! Unit in both. That is why it lives here rather than in either dissector: one
//! decoding, two carriers, the same reasoning that put the DER length rule in
//! [`super::der`].
//!
//! ## The bit that matters most
//!
//! The cause-of-transmission byte carries a **negative** flag alongside the
//! cause itself. `ActCon` means "activation confirmed"; `ActCon` with that flag
//! set means the substation **refused the command**. The two differ by one bit
//! and read identically in any tool that reports only the cause.
//!
//! On a control network that distinction is the whole message: it is the
//! difference between a breaker that opened and a breaker that was told to open
//! and did not. The test flag matters for the same reason in reverse — a
//! command marked as test should not have operated anything at all.

/// Type ID, variable structure qualifier, cause, originator, common address.
pub(crate) const HEADER_LEN: usize = 6;

const CAUSE_MASK: u8 = 0x3F;
const NEGATIVE_FLAG: u8 = 0x40;
const TEST_FLAG: u8 = 0x80;

/// What kind of information the message carries.
fn type_name(type_id: u8) -> Option<&'static str> {
    Some(match type_id {
        1 => "single-point status",
        3 => "double-point status",
        5 => "step position",
        7 => "32-bit bitstring",
        9 => "measured value (normalised)",
        11 => "measured value (scaled)",
        13 => "measured value (float)",
        15 => "integrated total",
        30 => "single-point status with time",
        31 => "double-point status with time",
        45 => "single command",
        46 => "double command",
        47 => "regulating step command",
        48 => "set point (normalised)",
        49 => "set point (scaled)",
        50 => "set point (float)",
        70 => "end of initialisation",
        100 => "interrogation command",
        101 => "counter interrogation command",
        103 => "clock synchronisation",
        105 => "reset process command",
        _ => return None,
    })
}

/// Why the message was sent.
fn cause_name(cause: u8) -> Option<&'static str> {
    Some(match cause {
        1 => "cyclic",
        2 => "background scan",
        3 => "spontaneous",
        4 => "initialised",
        5 => "requested",
        6 => "activation",
        7 => "activation confirmed",
        8 => "deactivation",
        9 => "deactivation confirmed",
        10 => "activation terminated",
        11 => "returned by remote command",
        12 => "returned by local command",
        13 => "file transfer",
        20 => "response to general interrogation",
        21..=36 => "response to group interrogation",
        37 => "response to counter interrogation",
        44 => "unknown type identifier",
        45 => "unknown cause of transmission",
        46 => "unknown common address",
        47 => "unknown information object address",
        _ => return None,
    })
}

/// A decoded ASDU header.
pub(crate) struct Asdu {
    pub type_id: u8,
    pub cause: u8,
    /// The substation this message is about.
    pub common_address: u16,
    /// The command was refused rather than carried out.
    pub negative: bool,
    /// Marked as a test, so nothing should have physically operated.
    pub test: bool,
    /// How many information objects follow.
    pub count: u8,
}

/// Read the ASDU header.
pub(crate) fn parse(payload: &[u8]) -> Option<Asdu> {
    let head = payload.get(..HEADER_LEN)?;
    Some(Asdu {
        type_id: head[0],
        // The high bit of the qualifier says whether the objects share a
        // sequence; the count is the remaining seven bits, so reading the byte
        // whole doubles the count on every sequential message.
        count: head[1] & 0x7F,
        cause: head[2] & CAUSE_MASK,
        negative: head[2] & NEGATIVE_FLAG != 0,
        test: head[2] & TEST_FLAG != 0,
        // The common address is little-endian, unlike most of what a network
        // engineer reads.
        common_address: u16::from_le_bytes([head[4], head[5]]),
    })
}

/// Render an ASDU as the part of a summary that says what happened.
pub(crate) fn describe(asdu: &Asdu) -> String {
    let what = match type_name(asdu.type_id) {
        Some(name) => name.to_string(),
        // A type the standard has not assigned keeps its number rather than
        // being mapped to whichever entry was nearest.
        None => format!("type {}", asdu.type_id),
    };
    let why = match cause_name(asdu.cause) {
        Some(name) => name.to_string(),
        None => format!("cause {}", asdu.cause),
    };

    let mut summary = format!("station {} — {what}, {why}", asdu.common_address);

    // The refusal is the news, so it goes where it cannot be missed.
    if asdu.negative {
        summary = format!(
            "station {} — {what} REFUSED ({why}, negative)",
            asdu.common_address
        );
    }
    if asdu.test {
        summary.push_str(" [test]");
    }
    if asdu.count > 1 {
        summary.push_str(&format!(" ×{}", asdu.count));
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an ASDU header.
    fn asdu(type_id: u8, count: u8, cause: u8, station: u16) -> Vec<u8> {
        let mut v = vec![type_id, count, cause, 0x00];
        v.extend_from_slice(&station.to_le_bytes());
        v
    }

    /// The reason this module exists: a command that was refused and a command
    /// that was confirmed differ by one bit.
    #[test]
    fn a_refused_command_is_not_a_confirmed_one() {
        // Single command, activation confirmed.
        let confirmed = parse(&asdu(45, 1, 7, 12)).expect("an ASDU");
        assert_eq!(
            describe(&confirmed),
            "station 12 — single command, activation confirmed"
        );

        // The same message with the negative flag set.
        let refused = parse(&asdu(45, 1, 7 | NEGATIVE_FLAG, 12)).expect("an ASDU");
        assert!(refused.negative);
        assert_eq!(
            describe(&refused),
            "station 12 — single command REFUSED (activation confirmed, negative)"
        );
    }

    /// A test command should not have operated anything, which is worth saying
    /// next to one that looks otherwise identical.
    #[test]
    fn a_test_message_is_flagged() {
        let test = parse(&asdu(46, 1, 6 | TEST_FLAG, 3)).expect("an ASDU");
        assert!(test.test);
        assert!(describe(&test).ends_with("[test]"), "{}", describe(&test));
    }

    /// The count shares a byte with the sequence flag. Read whole, every
    /// sequential message reports more than a hundred extra objects.
    #[test]
    fn the_object_count_excludes_the_sequence_flag() {
        let sequential = parse(&asdu(9, 0x80 | 4, 20, 1)).expect("an ASDU");
        assert_eq!(sequential.count, 4);
        assert!(describe(&sequential).contains("×4"));
    }

    /// The common address is little-endian, unlike most network fields.
    #[test]
    fn the_station_address_is_little_endian() {
        let a = parse(&asdu(1, 1, 3, 0x0102)).expect("an ASDU");
        assert_eq!(a.common_address, 0x0102);
        assert!(describe(&a).contains("station 258"));
    }

    /// The messages that move a breaker are named apart from the ones that
    /// merely report.
    #[test]
    fn commands_and_measurements_are_distinguished() {
        let command = parse(&asdu(46, 1, 6, 1)).expect("an ASDU");
        assert!(describe(&command).contains("double command"));
        let measurement = parse(&asdu(13, 1, 3, 1)).expect("an ASDU");
        assert!(describe(&measurement).contains("measured value (float)"));
        let interrogation = parse(&asdu(100, 1, 6, 1)).expect("an ASDU");
        assert!(describe(&interrogation).contains("interrogation command"));
    }

    /// Values outside the standard keep their numbers.
    #[test]
    fn unassigned_values_keep_their_numbers() {
        let a = parse(&asdu(200, 1, 60, 1)).expect("an ASDU");
        let summary = describe(&a);
        assert!(summary.contains("type 200"), "{summary}");
        assert!(summary.contains("cause 60"), "{summary}");
    }

    #[test]
    fn truncated_does_not_panic() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[1, 1, 3, 0, 1]).is_none());
        assert!(parse(&asdu(1, 1, 3, 1)).is_some());
    }
}
