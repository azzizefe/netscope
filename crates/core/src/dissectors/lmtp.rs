// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! LMTP — the last hop, where mail is actually filed (RFC 2033).
//!
//! LMTP looks like SMTP and shares most of its verbs, but it is used for a
//! different job: handing a message from the mail server to the thing that
//! stores it. Dovecot, Cyrus and Postfix's local delivery all speak it.
//!
//! The one difference that matters is at the end. SMTP answers a delivery with
//! a single status for the whole message; LMTP answers with **one status per
//! recipient**. That is the whole reason the protocol exists — a message to
//! five mailboxes can succeed for four and fail for the fifth, and only here is
//! that visible. A message that "was delivered" but is missing from one mailbox
//! is exactly this, and nothing upstream records it.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// What a status code means, by its first digit.
fn status_meaning(code: u16) -> &'static str {
    match code / 100 {
        2 => "delivered",
        3 => "continue",
        4 => "temporary failure",
        5 => "permanent failure",
        _ => "status",
    }
}

/// Whether a payload is LMTP rather than SMTP.
///
/// The greeting verb is the only reliable difference: LMTP uses `LHLO` where
/// SMTP uses `HELO` or `EHLO`. Everything after that is indistinguishable, so
/// recognition rests on the port and this one command.
pub(crate) fn looks_like_lmtp(payload: &[u8]) -> bool {
    payload.len() >= 4 && payload[..4].eq_ignore_ascii_case(b"LHLO")
}

/// Dissect an LMTP message (TCP 24).
pub fn dissect_lmtp(
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
        protocol: Protocol::Lmtp,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    let Ok(text) = std::str::from_utf8(payload) else {
        return format!("LMTP ({})", super::bytes(payload.len() as u64));
    };
    let first = text.lines().next().unwrap_or("").trim_end();
    if first.is_empty() {
        return "LMTP".to_string();
    }

    // A reply opens with a three-digit code. Several replies can arrive in one
    // segment — one per recipient — and the count is the useful part, because a
    // partial delivery is the failure this protocol exists to report.
    if let Some(code) = first
        .get(..3)
        .and_then(|c| c.parse::<u16>().ok())
        .filter(|&c| (200..600).contains(&c))
    {
        let replies: Vec<u16> = text
            .lines()
            .filter_map(|l| l.get(..3).and_then(|c| c.parse::<u16>().ok()))
            .filter(|&c| (200..600).contains(&c))
            .collect();
        // A mixed batch is the case worth naming: some mailboxes took the
        // message and some did not, which no single status could express.
        let failed = replies.iter().filter(|&&c| c >= 400).count();
        if replies.len() > 1 && failed > 0 && failed < replies.len() {
            return format!("LMTP {} of {} recipients failed", failed, replies.len());
        }
        if replies.len() > 1 {
            return format!(
                "LMTP {} — {} recipients",
                status_meaning(code),
                replies.len()
            );
        }
        return format!("LMTP {code} {}", super::truncate(first[3..].trim(), 50));
    }

    // Otherwise it is a command from the mail server.
    format!("LMTP {}", super::truncate(first, 60))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reason LMTP exists rather than reusing SMTP: a per-recipient answer,
    /// so a message can succeed for some mailboxes and fail for others.
    #[test]
    fn a_partial_delivery_is_reported_as_partial() {
        let reply = "250 2.0.0 <a@x> Saved\r\n\
                     250 2.0.0 <b@x> Saved\r\n\
                     550 5.1.1 <c@x> User unknown\r\n";
        let r = dissect_lmtp(None, None, 24, 50000, reply.as_bytes());
        assert_eq!(r.protocol, Protocol::Lmtp);
        assert_eq!(r.summary, "LMTP 1 of 3 recipients failed");
    }

    /// When every mailbox took it, that reads as a whole-batch success rather
    /// than being described as a failure of none.
    #[test]
    fn a_wholly_successful_batch_is_not_called_a_failure() {
        let reply = "250 2.0.0 <a@x> Saved\r\n250 2.0.0 <b@x> Saved\r\n";
        let summary = dissect_lmtp(None, None, 24, 1, reply.as_bytes()).summary;
        assert_eq!(summary, "LMTP delivered — 2 recipients");
        assert!(!summary.contains("failed"));
    }

    /// A single reply keeps its text, which carries the reason.
    #[test]
    fn a_single_reply_keeps_its_text() {
        let r = dissect_lmtp(None, None, 24, 1, b"550 5.1.1 User unknown\r\n");
        assert_eq!(r.summary, "LMTP 550 5.1.1 User unknown");
    }

    /// Commands from the mail server read as themselves.
    #[test]
    fn commands_are_shown() {
        assert_eq!(
            dissect_lmtp(None, None, 50000, 24, b"LHLO mail.example.com\r\n").summary,
            "LMTP LHLO mail.example.com"
        );
        assert!(dissect_lmtp(None, None, 50000, 24, b"RCPT TO:<bob@x>\r\n")
            .summary
            .contains("RCPT TO"));
    }

    /// LHLO is the only thing separating LMTP from SMTP on the wire, so
    /// recognition rests on it.
    #[test]
    fn recognition_rests_on_the_greeting_verb() {
        assert!(looks_like_lmtp(b"LHLO mail.example.com\r\n"));
        assert!(looks_like_lmtp(b"lhlo mail\r\n"));
        assert!(!looks_like_lmtp(b"EHLO mail.example.com\r\n"));
        assert!(!looks_like_lmtp(b"HELO mail\r\n"));
        assert!(!looks_like_lmtp(b""));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(b""), "LMTP");
        assert!(describe(&[0xFF, 0xFE]).starts_with("LMTP"));
        assert!(describe(b"25").starts_with("LMTP"));
    }
}
