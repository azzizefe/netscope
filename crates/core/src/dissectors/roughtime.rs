// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Roughtime — a time protocol you do not have to trust the server for.
//!
//! NTP has an awkward property: a client has no way to prove its server lied.
//! A machine fed a wrong time will happily accept expired certificates or
//! reject valid ones. Roughtime fixes this by having every response signed and
//! by having clients chain servers together — each request carries a hash of
//! the previous server's answer, so a server that lies is caught by the next
//! one and the client ends up holding cryptographic proof of the deception.
//!
//! Times are deliberately coarse (the "radius" field says how uncertain the
//! answer is), because the point is detecting gross dishonesty, not
//! microsecond accuracy.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Newer versions frame every packet with this magic; the original Google
/// version did not, so its absence is not disqualifying.
const MAGIC: &[u8] = b"ROUGHTIM";
/// The framed form puts a four-byte length after the magic.
const FRAME_HEADER: usize = 12;

/// Tags that identify what a message is. Each is four bytes, padded with NULs.
const TAG_NONCE: &[u8; 4] = b"NONC";
const TAG_SIGNED_RESPONSE: &[u8; 4] = b"SREP";
const TAG_CERTIFICATE: &[u8; 4] = b"CERT";

/// A tag count beyond this is not a Roughtime message.
const MAX_TAGS: u32 = 64;

/// Whether a payload is a Roughtime message, strictly enough to claim it on a
/// port we were not expecting.
///
/// Only the framed form qualifies. Deployments really do use assorted ports —
/// 2002 and 2003 are both in the wild — so a structural check earns its keep,
/// but the unframed legacy form is just a tag list and is far too weak to
/// claim arbitrary traffic on. That form is still decoded when the port matches.
pub(crate) fn looks_like_roughtime(payload: &[u8]) -> bool {
    payload.starts_with(MAGIC) && parse(payload).is_some()
}

/// Read the tag list, returning the tags present.
///
/// The message is a count, then that many offsets minus one, then the tags
/// themselves, then the values. Only the tags are needed to say what kind of
/// message this is.
fn tags(message: &[u8]) -> Option<Vec<[u8; 4]>> {
    let count = u32::from_le_bytes([
        *message.first()?,
        *message.get(1)?,
        *message.get(2)?,
        *message.get(3)?,
    ]);
    if count == 0 || count > MAX_TAGS {
        return None;
    }
    // 4 bytes of count, then (count - 1) offsets, then the tags.
    let tags_start = 4 + (count as usize - 1) * 4;
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let at = tags_start + i * 4;
        let tag = message.get(at..at + 4)?;
        out.push([tag[0], tag[1], tag[2], tag[3]]);
    }
    Some(out)
}

/// Parse a message, returning its tags whether or not it is framed.
fn parse(payload: &[u8]) -> Option<Vec<[u8; 4]>> {
    if payload.starts_with(MAGIC) {
        return tags(payload.get(FRAME_HEADER..)?);
    }
    // The unframed form has to look like a plausible tag list on its own, and
    // carry at least one tag we recognise — otherwise almost any four bytes
    // would pass.
    let found = tags(payload)?;
    let known = found
        .iter()
        .any(|t| t == TAG_NONCE || t == TAG_SIGNED_RESPONSE || t == TAG_CERTIFICATE);
    known.then_some(found)
}

/// Dissect a Roughtime message (UDP 2002).
pub fn dissect_roughtime(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match parse(payload) {
        Some(found) => {
            let has = |t: &[u8; 4]| found.iter().any(|f| f == t);
            // A response is what carries the signed time and the certificate
            // proving the key that signed it; a request only carries a nonce.
            if has(TAG_SIGNED_RESPONSE) {
                format!("Roughtime response — signed time, {} fields", found.len())
            } else if has(TAG_NONCE) {
                format!("Roughtime request — {} fields", found.len())
            } else {
                format!("Roughtime message — {} fields", found.len())
            }
        }
        None => format!("Roughtime ({})", super::bytes(payload.len() as u64)),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Roughtime,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a message body carrying the given tags.
    fn body(tags: &[&[u8; 4]]) -> Vec<u8> {
        let mut p = (tags.len() as u32).to_le_bytes().to_vec();
        // One offset per tag after the first.
        for i in 1..tags.len() {
            p.extend_from_slice(&((i * 64) as u32).to_le_bytes());
        }
        for t in tags {
            p.extend_from_slice(*t);
        }
        p.extend_from_slice(&[0u8; 64]); // the values themselves
        p
    }

    /// Wrap a body in the framed form.
    fn framed(tags: &[&[u8; 4]]) -> Vec<u8> {
        let b = body(tags);
        let mut p = MAGIC.to_vec();
        p.extend_from_slice(&(b.len() as u32).to_le_bytes());
        p.extend_from_slice(&b);
        p
    }

    #[test]
    fn request_carries_a_nonce() {
        let r = dissect_roughtime(None, None, 40000, 2002, &framed(&[b"NONC", b"PAD\x00"]));
        assert_eq!(r.protocol, Protocol::Roughtime);
        assert_eq!(r.summary, "Roughtime request — 2 fields");
    }

    /// The signed response is what makes the protocol worth using, so it has to
    /// read differently from a request.
    #[test]
    fn response_carries_the_signed_time() {
        let r = dissect_roughtime(
            None,
            None,
            2002,
            40000,
            &framed(&[b"SIG\x00", b"PATH", b"SREP", b"CERT", b"INDX"]),
        );
        assert_eq!(r.summary, "Roughtime response — signed time, 5 fields");
    }

    /// The original version sent no magic, so both forms have to decode.
    #[test]
    fn framed_and_unframed_both_decode() {
        let with_magic = dissect_roughtime(None, None, 1, 2002, &framed(&[b"NONC", b"PAD\x00"]));
        let without = dissect_roughtime(None, None, 1, 2002, &body(&[b"NONC", b"PAD\x00"]));
        assert_eq!(with_magic.summary, without.summary);
    }

    /// Without the magic, a tag list alone is weak evidence, so at least one
    /// recognised tag is required before parsing it at all.
    #[test]
    fn unframed_payload_needs_a_known_tag() {
        assert!(parse(&body(&[b"AAAA", b"BBBB"])).is_none());
        assert!(parse(&body(&[b"NONC"])).is_some());
    }

    /// The structural check is stricter than the parser: it claims only the
    /// framed form, because an unframed tag list would match too much to be
    /// safe on a port we were not expecting.
    #[test]
    fn only_the_framed_form_is_claimed_structurally() {
        assert!(looks_like_roughtime(&framed(&[b"NONC"])));
        assert!(!looks_like_roughtime(&body(&[b"NONC"])));
    }

    #[test]
    fn foreign_payloads_are_not_claimed() {
        assert!(!looks_like_roughtime(b"GET / HTTP/1.1\r\n\r\n"));
        assert!(!looks_like_roughtime(&[]));
        assert!(!looks_like_roughtime(&[0u8; 16]));
    }

    /// An implausible tag count means we are misreading, not looking at a
    /// message with thousands of fields.
    #[test]
    fn implausible_tag_count_is_rejected() {
        let mut p = 9_999u32.to_le_bytes().to_vec();
        p.extend_from_slice(&[0u8; 32]);
        assert!(!looks_like_roughtime(&p));
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_roughtime(None, None, 1, 2002, &[0x02, 0x00]);
        assert_eq!(r.summary, "Roughtime (2 bytes)");
    }
}
