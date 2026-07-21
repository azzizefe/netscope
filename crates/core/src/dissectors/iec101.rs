// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! IEC 60870-5-101 — the serial telecontrol link (FT1.2 framing).
//!
//! The same telecontrol messages as [`super::iec104`], carried over a serial
//! line instead of TCP. Substations reached by leased line, radio or dial-up
//! still speak this, and gateways forward it onto IP exactly as Modbus gateways
//! forward RTU — so it turns up on captures that ought to contain nothing but
//! Ethernet.
//!
//! The message inside is the same ASDU, decoded by [`super::iec_asdu`]. What
//! differs is the frame around it, and that frame carries something -104 does
//! not.
//!
//! ## What the link layer says
//!
//! FT1.2 is a request-response link with a control byte in every frame, and two
//! bits of it are worth reading:
//!
//! * **NACK — link busy.** The outstation refusing a message outright, at the
//!   link layer, before any ASDU is involved. A control centre seeing a command
//!   time out has no way to tell this from a lost frame unless the link layer
//!   is read.
//! * **DFC — data flow control.** The outstation saying its buffers are full
//!   and it cannot accept more. On a slow serial link this is how an overloaded
//!   RTU announces itself, and it is the reason polling appears to stall while
//!   the line itself is perfectly healthy.
//!
//! The variable-length frame also repeats its length byte and its start byte,
//! which is what makes recognition on a byte stream safe.

use std::net::IpAddr;

use crate::models::Protocol;

use super::{iec_asdu, DissectedResult};

const VARIABLE_START: u8 = 0x68;
const FIXED_START: u8 = 0x10;
const SINGLE_CHAR: u8 = 0xE5;
const STOP: u8 = 0x16;

/// The link address is one byte in the common configuration; the standard also
/// allows two, which cannot be told apart without knowing the deployment.
const LINK_ADDRESS_LEN: usize = 1;

/// PRM: set when the frame comes from the initiating station.
const PRM_FLAG: u8 = 0x40;
/// DFC, in a frame from the outstation: its buffers are full.
const DFC_FLAG: u8 = 0x10;
const FUNCTION_MASK: u8 = 0x0F;

/// What the controlling station is asking for.
fn primary_function(code: u8) -> &'static str {
    match code {
        0 => "reset remote link",
        1 => "reset user process",
        3 | 4 => "user data",
        8 => "expected response specifies access demand",
        9 => "request link status",
        10 => "poll for class 1 data",
        11 => "poll for class 2 data",
        _ => "link function",
    }
}

/// What the outstation is answering.
fn secondary_function(code: u8) -> &'static str {
    match code {
        0 => "ACK",
        1 => "NACK — message not accepted, link busy",
        8 => "user data",
        9 => "no user data available",
        11 => "link status",
        14 => "link service not functioning",
        15 => "link service not implemented",
        _ => "link response",
    }
}

/// Whether a payload is an FT1.2 frame.
///
/// A variable-length frame repeats both its start byte and its length, and ends
/// with a fixed stop byte. That redundancy is deliberate — it is what makes the
/// format recoverable on a serial line — and it is strong enough to recognise
/// on, which matters because there is no port or magic otherwise.
pub(crate) fn looks_like_iec101(payload: &[u8]) -> bool {
    match payload.first() {
        Some(&SINGLE_CHAR) => payload.len() == 1,
        Some(&FIXED_START) => {
            // Start, control, address, checksum, stop.
            payload.len() == 4 + LINK_ADDRESS_LEN && payload.last() == Some(&STOP)
        }
        Some(&VARIABLE_START) => {
            let Some(head) = payload.get(..4) else {
                return false;
            };
            // The length is sent twice and the start byte repeated; a frame
            // that disagrees with itself is not one.
            head[1] == head[2] && head[3] == VARIABLE_START && head[1] > 0 && {
                // Start(4) + user data + checksum + stop.
                payload.len() == 4 + head[1] as usize + 2 && payload.last() == Some(&STOP)
            }
        }
        _ => false,
    }
}

/// Dissect an IEC 60870-5-101 frame.
pub fn dissect_iec101(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Iec101,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    match payload.first() {
        // The shortest frame in the protocol: a bare positive acknowledgement.
        Some(&SINGLE_CHAR) => "IEC 101 — single-character ACK".to_string(),
        Some(&FIXED_START) => match payload.get(1) {
            Some(&control) => format!("IEC 101 {}", link_control(control)),
            None => "IEC 101 fixed-length frame".to_string(),
        },
        Some(&VARIABLE_START) => {
            let Some(&control) = payload.get(4) else {
                return "IEC 101 variable-length frame".to_string();
            };
            let link = link_control(control);
            // The ASDU sits after the control field and the link address, and
            // is the same structure -104 carries.
            let asdu_at = 5 + LINK_ADDRESS_LEN;
            match payload.get(asdu_at..).and_then(iec_asdu::parse) {
                Some(asdu) => format!("IEC 101 {}", iec_asdu::describe(&asdu)),
                None => format!("IEC 101 {link}"),
            }
        }
        _ => "IEC 101".to_string(),
    }
}

/// Read the control byte, which says who is speaking and what they want.
fn link_control(control: u8) -> String {
    let code = control & FUNCTION_MASK;
    if control & PRM_FLAG != 0 {
        primary_function(code).to_string()
    } else {
        let what = secondary_function(code);
        // The outstation's flow-control bit is the reason polling stalls on a
        // link that is otherwise perfectly healthy.
        if control & DFC_FLAG != 0 {
            format!("{what} [DFC — outstation buffers full]")
        } else {
            what.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a variable-length frame carrying the given user data.
    fn variable(control: u8, address: u8, user: &[u8]) -> Vec<u8> {
        let len = (2 + user.len()) as u8; // control + address + ASDU
        let mut v = vec![VARIABLE_START, len, len, VARIABLE_START, control, address];
        v.extend_from_slice(user);
        let checksum = v[4..].iter().fold(0u8, |a, &b| a.wrapping_add(b));
        v.push(checksum);
        v.push(STOP);
        v
    }

    /// Build a fixed-length frame, which carries no ASDU.
    fn fixed(control: u8, address: u8) -> Vec<u8> {
        let checksum = control.wrapping_add(address);
        vec![FIXED_START, control, address, checksum, STOP]
    }

    /// The reason this dissector exists: the same telecontrol content as -104,
    /// on a link a great many substations are still reached by.
    #[test]
    fn a_variable_frame_reports_the_asdu_inside_it() {
        // Single command, activation confirmed with the negative flag: the
        // substation refused.
        let asdu = [45u8, 1, 7 | 0x40, 0x00, 0x0C, 0x00];
        let r = dissect_iec101(None, None, 0, 0, &variable(0x73, 1, &asdu));
        assert_eq!(r.protocol, Protocol::Iec101);
        assert_eq!(
            r.summary,
            "IEC 101 station 12 — single command REFUSED (activation confirmed, negative)"
        );
    }

    /// A link-layer refusal is a different failure from a lost frame, and only
    /// the control byte separates them.
    #[test]
    fn a_link_level_refusal_is_readable() {
        // From the outstation (PRM clear), function 1: NACK.
        assert_eq!(
            describe(&fixed(0x01, 1)),
            "IEC 101 NACK — message not accepted, link busy"
        );
    }

    /// The flow-control bit is why polling stalls on a healthy line.
    #[test]
    fn the_flow_control_bit_is_reported() {
        // Outstation ACK with DFC set.
        let summary = describe(&fixed(DFC_FLAG, 1));
        assert!(summary.contains("ACK"), "{summary}");
        assert!(summary.contains("outstation buffers full"), "{summary}");
    }

    /// The same function code means different things depending on which end
    /// sent it — code 1 is "reset user process" from the controlling station
    /// and "NACK" from the outstation.
    #[test]
    fn the_direction_bit_selects_the_function_table() {
        assert_eq!(
            describe(&fixed(PRM_FLAG | 1, 1)),
            "IEC 101 reset user process"
        );
        assert!(describe(&fixed(1, 1)).contains("NACK"));
        // And a poll, which is what most of a quiet link consists of.
        assert_eq!(
            describe(&fixed(PRM_FLAG | 11, 1)),
            "IEC 101 poll for class 2 data"
        );
    }

    /// The single-character acknowledgement is the whole frame.
    #[test]
    fn the_single_character_ack_is_recognised() {
        assert!(looks_like_iec101(&[SINGLE_CHAR]));
        assert_eq!(describe(&[SINGLE_CHAR]), "IEC 101 — single-character ACK");
    }

    /// Recognition rests on the frame's own redundancy: the length is sent
    /// twice, the start byte repeated, and the stop byte fixed.
    #[test]
    fn recognition_rests_on_the_frames_redundancy() {
        let good = variable(0x73, 1, &[45, 1, 7, 0, 1, 0]);
        assert!(looks_like_iec101(&good));

        // The two length bytes disagreeing means this is not a frame.
        let mut mismatched = good.clone();
        mismatched[2] ^= 0x01;
        assert!(!looks_like_iec101(&mismatched));

        // The repeated start byte missing.
        let mut no_repeat = good.clone();
        no_repeat[3] = 0x00;
        assert!(!looks_like_iec101(&no_repeat));

        // No stop byte.
        let mut no_stop = good.clone();
        let n = no_stop.len();
        no_stop[n - 1] = 0x00;
        assert!(!looks_like_iec101(&no_stop));

        assert!(!looks_like_iec101(b"GET / HTTP/1.1\r\n"));
        assert!(!looks_like_iec101(&[]));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "IEC 101");
        assert_eq!(describe(&[FIXED_START]), "IEC 101 fixed-length frame");
        assert_eq!(
            describe(&[VARIABLE_START, 2, 2, VARIABLE_START]),
            "IEC 101 variable-length frame"
        );
        // A variable frame whose ASDU is cut short falls back to the link layer.
        let short = variable(0x73, 1, &[45, 1]);
        assert_eq!(describe(&short), "IEC 101 user data");
    }
}
