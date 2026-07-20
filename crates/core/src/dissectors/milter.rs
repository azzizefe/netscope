// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Milter — the filter that decides whether mail lives or dies (TCP 8891).
//!
//! A mail server hands each message to its filters — spam scoring, signing,
//! virus scanning, policy — one command at a time, and each filter answers.
//! This is that conversation.
//!
//! It is worth reading because of one answer in particular. `discard` tells the
//! server to accept the message and then silently throw it away: the sender gets
//! a success response, the recipient never receives anything, and no bounce is
//! generated. Mail that vanishes without a trace anywhere in the logs is
//! usually this, and the capture is the only place it is visible.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// What the mail server is telling the filter about.
fn command_name(command: u8) -> Option<&'static str> {
    Some(match command {
        b'O' => "option negotiation",
        b'C' => "connection",
        b'H' => "HELO",
        b'M' => "sender",
        b'R' => "recipient",
        b'L' => "header",
        b'N' => "end of headers",
        b'B' => "body",
        b'E' => "end of body",
        b'A' => "abort",
        b'Q' => "quit",
        b'D' => "macros",
        _ => return None,
    })
}

/// What the filter is telling the mail server to do.
fn response_name(response: u8) -> Option<&'static str> {
    Some(match response {
        b'c' => "continue",
        b'a' => "accept the message",
        b'r' => "reject the message",
        b'd' => "discard silently (the sender is told it was accepted)",
        b't' => "temporary failure, retry later",
        b'p' => "no further callbacks needed",
        b'y' => "reply with this code",
        b'q' => "quarantine",
        b'+' => "add a recipient",
        b'-' => "remove a recipient",
        b'b' => "replace the body",
        b'h' => "add a header",
        b'm' => "change a header",
        _ => return None,
    })
}

/// Whether a payload is a milter message: a length that agrees with what
/// follows, and a byte that is one of the protocol's letters.
pub(crate) fn looks_like_milter(payload: &[u8]) -> bool {
    let Some(len) = payload
        .get(..4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
    else {
        return false;
    };
    // The length counts the command byte, so it is never zero, and a milter
    // message is small — a bogus length is what rules out other traffic.
    if len == 0 || len > 65536 || payload.len() < 5 {
        return false;
    }
    let byte = payload[4];
    command_name(byte).is_some() || response_name(byte).is_some()
}

/// Dissect a milter message.
pub fn dissect_milter(
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
        protocol: Protocol::Milter,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    let Some(&byte) = payload.get(4) else {
        return "milter".to_string();
    };
    let body = payload.get(5..).unwrap_or(&[]);

    // A filter's verdict is the whole point of the exchange, so it is checked
    // first — the letters do not overlap between the two directions.
    if let Some(verdict) = response_name(byte) {
        return format!("milter — {verdict}");
    }
    let Some(command) = command_name(byte) else {
        return format!("milter (command '{}')", byte as char);
    };

    // The sender and recipient commands carry the address they are about, as
    // NUL-separated strings, and that is what makes a capture followable.
    if matches!(byte, b'M' | b'R') {
        if let Some(address) = body
            .split(|&b| b == 0)
            .find(|s| !s.is_empty())
            .and_then(|s| std::str::from_utf8(s).ok())
        {
            return format!("milter {command} — {}", super::truncate(address, 60));
        }
    }
    format!("milter {command}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a milter message: length, then the command byte and body.
    fn message(byte: u8, body: &[u8]) -> Vec<u8> {
        let mut p = ((body.len() + 1) as u32).to_be_bytes().to_vec();
        p.push(byte);
        p.extend_from_slice(body);
        p
    }

    /// The reason this dissector exists: mail that is accepted and then thrown
    /// away, with the sender told it succeeded and no bounce generated.
    #[test]
    fn a_silent_discard_is_spelled_out() {
        let r = dissect_milter(None, None, 8891, 50000, &message(b'd', &[]));
        assert_eq!(r.protocol, Protocol::Milter);
        assert!(r.summary.contains("discard silently"), "{}", r.summary);
        assert!(r.summary.contains("sender is told it was accepted"));
    }

    /// The other verdicts need to be distinguishable from it: a reject bounces,
    /// a temporary failure retries, an accept delivers.
    #[test]
    fn the_verdicts_are_distinguished() {
        for (byte, expected) in [
            (b'r', "reject"),
            (b't', "temporary failure"),
            (b'a', "accept"),
            (b'q', "quarantine"),
            (b'c', "continue"),
        ] {
            let summary = describe(&message(byte, &[]));
            assert!(summary.contains(expected), "{}: {summary}", byte as char);
        }
    }

    /// The addresses are what make a capture followable — which message was
    /// discarded, and for whom.
    #[test]
    fn the_sender_and_recipient_are_read() {
        assert_eq!(
            describe(&message(b'M', b"<alice@example.com>\0")),
            "milter sender — <alice@example.com>"
        );
        assert_eq!(
            describe(&message(b'R', b"<bob@example.org>\0")),
            "milter recipient — <bob@example.org>"
        );
    }

    /// The commands carrying no address read plainly.
    #[test]
    fn the_other_commands_are_named() {
        assert_eq!(describe(&message(b'C', &[])), "milter connection");
        assert_eq!(describe(&message(b'E', &[])), "milter end of body");
        assert_eq!(describe(&message(b'Q', &[])), "milter quit");
    }

    /// The length has to agree before a flow is claimed, so ordinary traffic on
    /// a nearby port is not read as a filter conversation.
    #[test]
    fn recognition_needs_a_plausible_length() {
        assert!(looks_like_milter(&message(b'C', &[0x00; 8])));
        assert!(!looks_like_milter(b"GET / HTTP/1.1\r\n\r\n"));
        assert!(!looks_like_milter(&[]));
        // A letter the protocol does not use.
        assert!(!looks_like_milter(&message(b'Z', &[])));
        // A length that could not be a milter message.
        let mut bad = message(b'C', &[]);
        bad[0..4].copy_from_slice(&0u32.to_be_bytes());
        assert!(!looks_like_milter(&bad));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "milter");
        assert_eq!(describe(&[0x00, 0x00, 0x00, 0x01]), "milter");
        assert!(describe(&message(b'M', &[])).starts_with("milter sender"));
    }
}
