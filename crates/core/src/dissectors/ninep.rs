// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! 9P — the Plan 9 filesystem protocol (TCP 564).
//!
//! Worth decoding because of where it turns up now rather than where it came
//! from: WSL2 serves the Windows filesystem to Linux over 9P, QEMU shares
//! directories with guests over it, and several container runtimes use it. So a
//! developer's slow file access on WSL is a 9P problem, and every operation is
//! visible here in the clear.
//!
//! Every message carries a tag pairing a request with its reply, which is what
//! makes a slow operation identifiable in an interleaved capture.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Size, type, tag — then the message body.
const HEADER: usize = 7;

/// Message types (9P2000). Requests are even, replies odd, and the pairing is
/// deliberate: `Twalk` is 110 and `Rwalk` is 111.
fn message_name(kind: u8) -> Option<&'static str> {
    Some(match kind {
        100 => "Tversion (negotiate)",
        101 => "Rversion",
        102 => "Tauth",
        103 => "Rauth",
        104 => "Tattach (mount)",
        105 => "Rattach",
        106 => "Terror (invalid)",
        107 => "Rerror (failed)",
        108 => "Tflush (cancel)",
        109 => "Rflush",
        110 => "Twalk (look up a path)",
        111 => "Rwalk",
        112 => "Topen",
        113 => "Ropen",
        114 => "Tcreate",
        115 => "Rcreate",
        116 => "Tread",
        117 => "Rread",
        118 => "Twrite",
        119 => "Rwrite",
        120 => "Tclunk (close)",
        121 => "Rclunk",
        122 => "Tremove",
        123 => "Rremove",
        124 => "Tstat",
        125 => "Rstat",
        126 => "Twstat",
        127 => "Rwstat",
        _ => return None,
    })
}

/// Read the header: the type, the tag, and the declared size.
///
/// Returns nothing when the declared size is implausible or the type is not one
/// of the twenty-eight defined, which is what keeps a non-9P payload on port 564
/// from being given an invented message name.
fn parse(payload: &[u8]) -> Option<(u8, u16, u32)> {
    let size = u32::from_le_bytes([
        *payload.first()?,
        *payload.get(1)?,
        *payload.get(2)?,
        *payload.get(3)?,
    ]);
    // The size covers the header, and a message larger than the usual maximum
    // message size means this is not a 9P boundary.
    if (size as usize) < HEADER || size > 1 << 20 {
        return None;
    }
    let kind = *payload.get(4)?;
    message_name(kind)?;
    let tag = u16::from_le_bytes([*payload.get(5)?, *payload.get(6)?]);
    Some((kind, tag, size))
}

/// Read the error text an `Rerror` carries, which is the reason an operation
/// failed and the most useful thing in the message.
fn error_text(payload: &[u8]) -> Option<String> {
    let len = u16::from_le_bytes([*payload.get(HEADER)?, *payload.get(HEADER + 1)?]) as usize;
    let text = payload.get(HEADER + 2..HEADER + 2 + len)?;
    let text = std::str::from_utf8(text).ok()?;
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

/// Dissect a 9P message.
pub fn dissect_9p(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match parse(payload) {
        Some((kind, tag, _)) => {
            let name = message_name(kind).unwrap_or("message");
            // An error reply carries the reason, which is what a reader wants
            // when something is not working.
            if kind == 107 {
                match error_text(payload) {
                    Some(text) => format!("9P Rerror — {} (tag {tag})", super::truncate(&text, 48)),
                    None => format!("9P Rerror (tag {tag})"),
                }
            } else {
                format!("9P {name} (tag {tag})")
            }
        }
        None => format!("9P ({})", super::bytes(payload.len() as u64)),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::NineP,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a 9P message of the given type, with `body` after the header.
    fn message(kind: u8, tag: u16, body: &[u8]) -> Vec<u8> {
        let size = (HEADER + body.len()) as u32;
        let mut p = size.to_le_bytes().to_vec();
        p.push(kind);
        p.extend_from_slice(&tag.to_le_bytes());
        p.extend_from_slice(body);
        p
    }

    /// The operations a developer actually waits on.
    #[test]
    fn file_operations_are_named() {
        let r = dissect_9p(None, None, 40000, 564, &message(116, 7, &[0u8; 12]));
        assert_eq!(r.protocol, Protocol::NineP);
        assert_eq!(r.summary, "9P Tread (tag 7)");
        assert_eq!(
            dissect_9p(None, None, 1, 564, &message(110, 3, &[])).summary,
            "9P Twalk (look up a path) (tag 3)"
        );
    }

    /// The error text is the reason an operation failed, and it travels in the
    /// clear — so it is the most useful field in the protocol.
    #[test]
    fn an_error_reply_carries_its_reason() {
        let reason = b"file does not exist";
        let mut body = (reason.len() as u16).to_le_bytes().to_vec();
        body.extend_from_slice(reason);
        let r = dissect_9p(None, None, 564, 1, &message(107, 42, &body));
        assert_eq!(r.summary, "9P Rerror — file does not exist (tag 42)");
    }

    /// The tag pairs a reply with its request, which is how a slow operation is
    /// found in an interleaved capture.
    #[test]
    fn the_tag_pairs_request_and_reply() {
        let request = dissect_9p(None, None, 1, 564, &message(116, 1234, &[]));
        let reply = dissect_9p(None, None, 564, 1, &message(117, 1234, &[]));
        assert!(request.summary.contains("tag 1234"));
        assert!(reply.summary.contains("tag 1234"));
    }

    /// A mount is where a session begins, and seeing one explains everything
    /// that follows.
    #[test]
    fn the_session_opening_is_named() {
        assert!(dissect_9p(None, None, 1, 564, &message(100, 65535, &[]))
            .summary
            .contains("Tversion (negotiate)"));
        assert!(dissect_9p(None, None, 1, 564, &message(104, 1, &[]))
            .summary
            .contains("Tattach (mount)"));
    }

    /// Traffic on port 564 that is not 9P must fall back to a byte count rather
    /// than being handed the name of whichever type the bytes resembled.
    #[test]
    fn foreign_payloads_are_not_given_a_message_name() {
        for payload in [
            b"GET / HTTP/1.1\r\n\r\n".as_slice(),
            &[0u8; 16],
            &message(200, 1, &[]), // a valid size, but no such type
        ] {
            let summary = dissect_9p(None, None, 1, 564, payload).summary;
            assert!(
                summary.starts_with("9P ("),
                "invented a message name: {summary}"
            );
        }
        assert!(parse(&message(116, 1, &[])).is_some());
    }

    /// A declared size smaller than the header, or implausibly large, means
    /// this is not a message boundary.
    #[test]
    fn implausible_sizes_are_rejected() {
        let mut small = message(116, 1, &[]);
        small[0..4].copy_from_slice(&3u32.to_le_bytes());
        assert!(parse(&small).is_none());

        let mut huge = message(116, 1, &[]);
        huge[0..4].copy_from_slice(&(1u32 << 24).to_le_bytes());
        assert!(parse(&huge).is_none());
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_9p(None, None, 1, 564, &[0x0B, 0x00]);
        assert_eq!(r.summary, "9P (2 bytes)");
    }
}
