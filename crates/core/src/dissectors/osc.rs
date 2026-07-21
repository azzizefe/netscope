// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! OSC — Open Sound Control, the control bus of a modern studio.
//!
//! OSC replaced MIDI for anything that needed more than seven bits of
//! resolution or a name longer than a number. A message is an address pattern
//! that looks like a filesystem path — `/mixer/1/fader` — a type-tag string
//! saying what the arguments are, and then the arguments themselves.
//!
//! It has no port of its own. Every application picks one, which is exactly why
//! reading it matters: on a show network the traffic is there but a capture
//! filtered by port finds nothing. The address pattern is what identifies both
//! the sender's intent and the device it is aimed at, and it is plain text.
//!
//! Bundles are the other half. A bundle carries several messages plus a time
//! tag saying when they should take effect, which is how a lighting cue and an
//! audio change stay together. A bundle whose time tag has already passed is
//! late — the receiver applies it immediately and the cue lands out of step.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Bundles open with this, where a message opens with its address.
const BUNDLE_TAG: &[u8] = b"#bundle\0";

/// Whether a payload is OSC.
///
/// A message begins with an address pattern, which always starts with a slash,
/// and everything is padded to a multiple of four bytes. Both are cheap and
/// exact, which matters because OSC has no port to be recognised by.
pub(crate) fn looks_like_osc(payload: &[u8]) -> bool {
    if !payload.len().is_multiple_of(4) || payload.len() < 4 {
        return false;
    }
    if payload.starts_with(BUNDLE_TAG) {
        return true;
    }
    // An address is printable ASCII up to its NUL padding.
    payload.first() == Some(&b'/')
        && payload
            .iter()
            .take_while(|&&b| b != 0)
            .all(|&b| (0x20..0x7f).contains(&b))
}

/// Dissect an OSC message or bundle.
pub fn dissect_osc(
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
        protocol: Protocol::Osc,
        summary: describe(payload),
    }
}

/// Read one NUL-terminated, four-byte-padded string.
fn osc_string(b: &[u8]) -> Option<(&str, usize)> {
    let end = b.iter().position(|&c| c == 0)?;
    let text = std::str::from_utf8(b.get(..end)?).ok()?;
    // Padding runs to the next multiple of four, counting the terminator.
    Some((text, (end + 1).div_ceil(4) * 4))
}

fn describe(payload: &[u8]) -> String {
    if payload.starts_with(BUNDLE_TAG) {
        // The time tag is NTP-format: seconds, then fraction. The single value
        // 1 means "immediately", which is a different thing from a timestamp.
        let immediate = payload.get(8..16) == Some(&[0, 0, 0, 0, 0, 0, 0, 1]);
        let count = count_bundle_elements(payload.get(16..).unwrap_or(&[]));
        return match (immediate, count) {
            (true, n) => format!("OSC bundle — {n} messages, immediate"),
            (false, n) => format!("OSC bundle — {n} messages, scheduled"),
        };
    }

    let Some((address, used)) = osc_string(payload) else {
        return "OSC".to_string();
    };
    // The type tags say what the arguments are, and are themselves a string
    // starting with a comma.
    match payload.get(used..).and_then(osc_string) {
        Some((tags, _)) if tags.starts_with(',') && !tags.is_empty() => {
            let count = tags.len() - 1;
            if count == 0 {
                format!("OSC {} — no arguments", super::truncate(address, 60))
            } else {
                format!(
                    "OSC {} — {count} argument{}",
                    super::truncate(address, 60),
                    if count == 1 { "" } else { "s" }
                )
            }
        }
        _ => format!("OSC {}", super::truncate(address, 60)),
    }
}

/// Count the elements in a bundle, each of which is length-prefixed.
fn count_bundle_elements(mut rest: &[u8]) -> usize {
    let mut count = 0;
    // A bundle with more elements than this is not something a console sends.
    while count < 64 {
        let Some(header) = rest.get(..4) else {
            break;
        };
        let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let Some(next) = rest.get(4 + length..) else {
            break;
        };
        count += 1;
        rest = next;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pad a string the way OSC does: NUL-terminated to a multiple of four.
    fn padded(s: &str) -> Vec<u8> {
        let mut v = s.as_bytes().to_vec();
        v.push(0);
        while !v.len().is_multiple_of(4) {
            v.push(0);
        }
        v
    }

    /// Build an OSC message with the given address and type tags.
    fn message(address: &str, tags: &str) -> Vec<u8> {
        let mut v = padded(address);
        v.extend_from_slice(&padded(tags));
        v
    }

    /// The reason this dissector exists: the address pattern says what is being
    /// controlled, in plain text, on a port nobody registered.
    #[test]
    fn the_address_pattern_is_reported() {
        let r = dissect_osc(None, None, 9000, 9001, &message("/mixer/1/fader", ",f"));
        assert_eq!(r.protocol, Protocol::Osc);
        assert_eq!(r.summary, "OSC /mixer/1/fader — 1 argument");
    }

    /// The type-tag string says how many arguments follow, and its leading
    /// comma is not one of them.
    #[test]
    fn the_argument_count_excludes_the_leading_comma() {
        assert!(describe(&message("/cue/go", ",iif")).contains("3 arguments"));
        assert!(describe(&message("/cue/go", ",")).contains("no arguments"));
    }

    /// A bundle groups changes that must take effect together, and its time tag
    /// says whether that is now or later.
    #[test]
    fn a_bundle_reports_its_count_and_whether_it_is_immediate() {
        let inner = message("/cue/go", ",i");
        let mut b = BUNDLE_TAG.to_vec();
        b.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]); // immediate
        b.extend_from_slice(&(inner.len() as u32).to_be_bytes());
        b.extend_from_slice(&inner);
        assert_eq!(describe(&b), "OSC bundle — 1 messages, immediate");

        // A real timestamp is scheduled rather than immediate.
        let mut scheduled = b.clone();
        scheduled[15] = 0x20;
        assert!(describe(&scheduled).contains("scheduled"));
    }

    /// OSC has no port of its own, so recognition has to be exact: an address
    /// that starts with a slash, and everything padded to four bytes.
    #[test]
    fn recognition_is_structural_because_there_is_no_port() {
        assert!(looks_like_osc(&message("/mixer/1/fader", ",f")));
        assert!(looks_like_osc(&{
            let mut b = BUNDLE_TAG.to_vec();
            b.extend_from_slice(&[0; 8]);
            b
        }));
        // Not slash-led.
        assert!(!looks_like_osc(&padded("mixer")));
        // Not padded to a multiple of four.
        assert!(!looks_like_osc(b"/abc"[..3].as_ref()));
        // Binary rubbish that happens to be the right length.
        assert!(!looks_like_osc(&[0xFF, 0xFE, 0xFD, 0xFC]));
        assert!(!looks_like_osc(&[]));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "OSC");
        // An address with no terminator.
        assert_eq!(describe(b"/abc"), "OSC");
        // An address with no type tags still names what is addressed.
        assert_eq!(describe(&padded("/ping")), "OSC /ping");
        // A bundle whose element length runs past the packet.
        let mut b = BUNDLE_TAG.to_vec();
        b.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
        b.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        assert_eq!(describe(&b), "OSC bundle — 0 messages, immediate");
    }
}
