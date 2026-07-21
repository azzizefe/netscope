// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! RTP-MIDI — MIDI over a network, and the session that carries it (RFC 6295).
//!
//! Musical instruments and lighting desks speak MIDI over a five-pin cable with
//! a hard length limit. RTP-MIDI carries it over IP instead, which is how a
//! keyboard reaches a computer three rooms away, and how Apple's "Network MIDI"
//! works.
//!
//! There are two conversations on adjacent ports. The control port runs Apple's
//! session protocol — invitation, accept or reject, then a clock
//! synchronisation exchange — and the data port carries the actual MIDI once
//! that succeeds.
//!
//! Reading the control port is the point. A session that never establishes
//! looks, at the instrument, like a cable that is not plugged in: no error, no
//! sound, nothing. The invitation being *rejected* rather than unanswered is a
//! completely different fault — the far end is there and refusing, usually
//! because it is already bound to another host or the name does not match.
//!
//! The clock exchange matters too. RTP-MIDI corrects for network delay by
//! measuring it three times per synchronisation round; if those rounds keep
//! repeating, timing is unstable and notes will arrive audibly late.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Every session-control packet opens with this.
const SIGNATURE: u16 = 0xFFFF;

/// The session commands, which are two ASCII letters each.
fn command_name(command: u16) -> Option<&'static str> {
    Some(match command {
        0x494E => "invitation",            // "IN"
        0x4E4F => "invitation rejected",   // "NO"
        0x4F4B => "invitation accepted",   // "OK"
        0x4259 => "end session",           // "BY"
        0x434B => "clock synchronisation", // "CK"
        0x5253 => "receiver feedback",     // "RS"
        0x524C => "bitrate limit",         // "RL"
        _ => return None,
    })
}

/// Whether a payload is an RTP-MIDI session-control packet.
pub(crate) fn looks_like_session(payload: &[u8]) -> bool {
    payload.get(..4).is_some_and(|b| {
        u16::from_be_bytes([b[0], b[1]]) == SIGNATURE
            && command_name(u16::from_be_bytes([b[2], b[3]])).is_some()
    })
}

/// Dissect an RTP-MIDI session-control packet.
pub fn dissect_rtpmidi(
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
        protocol: Protocol::RtpMidi,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    // Ports 5004/5005 also carry the RTP data stream, so the signature is what
    // separates a session-control packet from ordinary media.
    if !looks_like_session(payload) {
        return "RTP-MIDI stream".to_string();
    }
    let head = &payload[..4];
    let command = u16::from_be_bytes([head[2], head[3]]);
    let Some(name) = command_name(command) else {
        return "RTP-MIDI".to_string();
    };

    // The clock exchange numbers its rounds, and a count that keeps climbing is
    // a session that cannot settle on a delay estimate.
    //
    // Note the layout differs from the invitations: a clock packet carries no
    // protocol version and no initiator token, so its SSRC starts immediately
    // after the command and the count sits at offset 8, not 12.
    if command == 0x434B {
        if let Some(&count) = payload.get(8) {
            return format!("RTP-MIDI clock synchronisation — round {count}");
        }
    }

    // Invitations carry the participant's name, which is what an operator sees
    // in the instrument's own menu.
    if matches!(command, 0x494E | 0x4F4B | 0x4E4F) {
        if let Some(name_field) = payload.get(16..).and_then(|b| {
            let text: Vec<u8> = b.iter().copied().take_while(|&c| c != 0).collect();
            String::from_utf8(text).ok()
        }) {
            if !name_field.trim().is_empty() {
                return format!(
                    "RTP-MIDI {name} — '{}'",
                    super::truncate(name_field.trim(), 40)
                );
            }
        }
    }
    format!("RTP-MIDI {name}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a session-control packet.
    fn session(command: u16, tail: &[u8]) -> Vec<u8> {
        let mut p = SIGNATURE.to_be_bytes().to_vec();
        p.extend_from_slice(&command.to_be_bytes());
        p.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]); // protocol version
        p.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // initiator token
        p.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // SSRC
        p.extend_from_slice(tail);
        p
    }

    /// The reason this dissector exists: a refusal and silence look identical
    /// at the instrument, and are entirely different faults.
    #[test]
    fn a_rejection_is_distinguishable_from_an_acceptance() {
        let r = dissect_rtpmidi(None, None, 5004, 5004, &session(0x4E4F, b"Studio Mac\0"));
        assert_eq!(r.protocol, Protocol::RtpMidi);
        assert_eq!(r.summary, "RTP-MIDI invitation rejected — 'Studio Mac'");

        let accepted = describe(&session(0x4F4B, b"Studio Mac\0"));
        assert!(accepted.contains("invitation accepted"), "{accepted}");
    }

    /// The participant name is what appears in the instrument's own menu, so
    /// it is what an operator can match against.
    #[test]
    fn the_participant_name_is_read() {
        assert_eq!(
            describe(&session(0x494E, b"Keyboard 1\0")),
            "RTP-MIDI invitation — 'Keyboard 1'"
        );
    }

    /// Build a clock-synchronisation packet, which has its own shorter layout:
    /// no protocol version and no initiator token.
    fn clock(count: u8) -> Vec<u8> {
        let mut p = SIGNATURE.to_be_bytes().to_vec();
        p.extend_from_slice(&0x434Bu16.to_be_bytes());
        p.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // SSRC
        p.push(count);
        p.extend_from_slice(&[0, 0, 0]); // padding
        p
    }

    /// Clock rounds that keep climbing mean the delay estimate is not settling.
    ///
    /// The count sits at offset 8 because a clock packet carries neither the
    /// protocol version nor the initiator token that an invitation does —
    /// reading it at the invitation's offset gives whatever follows.
    #[test]
    fn the_clock_round_is_reported() {
        assert_eq!(
            describe(&clock(2)),
            "RTP-MIDI clock synchronisation — round 2"
        );
        assert_eq!(
            describe(&clock(0)),
            "RTP-MIDI clock synchronisation — round 0"
        );
    }

    #[test]
    fn the_other_commands_are_named() {
        assert_eq!(describe(&session(0x4259, &[])), "RTP-MIDI end session");
        assert_eq!(
            describe(&session(0x5253, &[])),
            "RTP-MIDI receiver feedback"
        );
    }

    /// The signature plus a known command is what identifies these, since the
    /// data port carries ordinary RTP that must not be claimed here.
    #[test]
    fn recognition_needs_both_the_signature_and_a_known_command() {
        assert!(looks_like_session(&session(0x494E, &[])));
        // Right signature, a command the protocol does not define.
        assert!(!looks_like_session(&[0xFF, 0xFF, 0x00, 0x01]));
        // A known command without the signature — an ordinary RTP header.
        assert!(!looks_like_session(&[0x80, 0x61, 0x49, 0x4E]));
        assert!(!looks_like_session(&[]));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "RTP-MIDI stream");
        assert_eq!(describe(&[0xFF, 0xFF, 0x49]), "RTP-MIDI stream");
        // An invitation with no name.
        assert_eq!(describe(&session(0x494E, &[])), "RTP-MIDI invitation");
        // A clock packet whose count byte has not arrived.
        assert_eq!(
            describe(&[0xFF, 0xFF, 0x43, 0x4B, 0, 0, 0, 1]),
            "RTP-MIDI clock synchronisation"
        );
    }
}
