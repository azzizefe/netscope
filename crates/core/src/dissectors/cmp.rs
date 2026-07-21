// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! CMP — how a device gets, renews and revokes its certificate (RFC 4210).
//!
//! Certificate Management Protocol is what runs underneath automated PKI: an
//! industrial controller, a phone or a car enrolling with a CA, then renewing
//! before its certificate expires, without anyone typing anything. It runs on
//! TCP 829 directly or inside an HTTP body.
//!
//! ## Why an enrolment failure is worth catching
//!
//! When enrolment fails, the device usually cannot do its job at all — it has
//! no identity, so nothing will talk to it — and it fails on a schedule nobody
//! is watching, because renewal happens weeks or months after installation.
//! The failure that matters is not the one at the moment of deployment but the
//! one at 3am on a device that has been fine for a year.
//!
//! CMP says exactly what went wrong. The `error` body carries a status and a
//! bitfield of reasons: the clock is off (`badTime`), the request was signed
//! with a key the CA does not trust (`signerNotTrusted`), the proof of
//! possession failed (`badPOP`), the CA is simply not accepting requests right
//! now (`systemUnavail`). Those need entirely different fixes and a device log
//! will usually record only "enrolment failed".
//!
//! ## Structure
//!
//! The message type is a context tag on the body, so it is readable from the
//! DER alone without the schema — which is what makes this decodable at all.
//! See [`super::der`].

use std::net::IpAddr;

use crate::models::Protocol;

use super::{der, pkix, DissectedResult};

/// Content type used when CMP travels inside HTTP rather than on port 829.
pub(crate) fn is_cmp_type(content_type: &str) -> bool {
    content_type == "application/pkixcmp"
}

/// What the message is, from the body's context tag.
fn body_name(tag: u8) -> Option<&'static str> {
    Some(match tag {
        0 => "initialisation request",
        1 => "initialisation response",
        2 => "certification request",
        3 => "certification response",
        4 => "PKCS#10 certification request",
        5 | 6 => "proof-of-possession challenge",
        7 => "key update request",
        8 => "key update response",
        9 => "key recovery request",
        10 => "key recovery response",
        11 => "revocation request",
        12 => "revocation response",
        13 => "cross-certification request",
        14 => "cross-certification response",
        15 => "CA key update announcement",
        16 => "certificate announcement",
        17 => "revocation announcement",
        18 => "CRL announcement",
        19 => "confirmation",
        20 => "nested message",
        21 => "general message",
        22 => "general response",
        23 => "error",
        24 => "certificate confirmation",
        25 => "poll request",
        26 => "poll response",
        _ => return None,
    })
}

/// Reasons, which arrive as a bit string rather than a number — several can be
/// set at once and reporting only the first would lose the rest.
const FAILURES: &[(u32, &str)] = &[
    (0, "bad algorithm"),
    (1, "bad message check — the signature did not verify"),
    (2, "bad request"),
    (3, "bad time — the device's clock is wrong"),
    (4, "bad certificate id"),
    (5, "bad data format"),
    (6, "wrong authority"),
    (7, "incorrect data"),
    (8, "missing timestamp"),
    (9, "bad proof of possession"),
    (10, "certificate revoked"),
    (11, "certificate confirmed"),
    (12, "wrong integrity"),
    (13, "bad recipient nonce"),
    (14, "time not available"),
    (15, "unaccepted policy"),
    (16, "unaccepted extension"),
    (17, "added protection not permitted"),
    (18, "bad sender nonce"),
    (19, "bad certificate template"),
    (20, "signer not trusted"),
    (21, "transaction id in use"),
    (22, "unsupported version"),
    (23, "not authorised"),
    (24, "system unavailable — the CA is not accepting requests"),
    (25, "system failure"),
    (26, "duplicate certificate request"),
];

/// Whether a payload is a CMP message.
///
/// A PKIMessage is a DER SEQUENCE whose first member is the header, itself a
/// SEQUENCE. That is weak on its own, which is why it is only applied on the
/// assigned port or a matching content type.
pub(crate) fn looks_like_cmp(payload: &[u8]) -> bool {
    der::read(payload)
        .filter(|t| t.tag == 0x30)
        .and_then(|outer| der::read(outer.value))
        .is_some_and(|header| header.tag == 0x30)
}

/// Dissect a CMP message.
pub fn dissect_cmp(
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
        protocol: Protocol::Cmp,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    // 829 is assigned to CMP, but something else squatting there should not be
    // described as a certificate request.
    if !looks_like_cmp(payload) {
        return "CMP (not a PKIMessage)".to_string();
    }
    // PKIMessage ::= SEQUENCE { header PKIHeader, body PKIBody, ... }
    let Some(message) = der::read(payload).filter(|t| t.tag == 0x30) else {
        return "CMP".to_string();
    };
    // The body is the *second* member and its context tag is the message type.
    //
    // Taking it by position rather than by searching for a context tag matters
    // because `protection` and `extraCerts` that follow it are context-tagged
    // too — and `protection` is [0], which is also `ir`. On a message whose
    // body is absent or unreadable, a search finds the protection and reports
    // an initialisation request that was never sent.
    let mut members = der::children(message.value);
    let Some(_header) = members.next() else {
        return "CMP".to_string();
    };
    let Some(body) = members.next() else {
        return "CMP".to_string();
    };
    let Some(tag) = body.context_tag() else {
        return "CMP".to_string();
    };
    // `protection` is `[0] IMPLICIT BIT STRING` — primitive — while every body
    // alternative that shares tag 0 (`ir`) is constructed. On a message whose
    // body is missing, position alone lands on the protection and would report
    // an initialisation request nobody sent; the constructed bit is what
    // separates them, and it is visible in the encoding.
    if tag == 0 && !body.is_constructed() {
        return "CMP".to_string();
    }
    let Some(name) = body_name(tag) else {
        return format!("CMP (body {tag})");
    };

    // An error, and the responses that can carry a rejection, hold a
    // PKIStatusInfo — which is where the reason lives.
    match status_info(body.value) {
        Some(text) => format!("CMP {name} — {text}"),
        None => format!("CMP {name}"),
    }
}

/// Read the status info that an error or a rejection carries.
///
/// The parsing lives in [`super::pkix`] because the timestamp protocol answers
/// with the identical structure; only the meaning of the bits differs.
fn status_info(body: &[u8]) -> Option<String> {
    let parsed = pkix::parse(body, FAILURES)?;
    let outcome = match parsed.status {
        // CMP calls zero "accepted"; the timestamp protocol calls it "granted".
        0 => "accepted".to_string(),
        other => match pkix::status_name(other) {
            Some(name) => name.to_string(),
            // A status outside the standard keeps its number.
            None => format!("status {other}"),
        },
    };
    if parsed.reasons.is_empty() {
        Some(outcome)
    } else {
        Some(format!("{outcome}: {}", parsed.reasons.join(", ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        assert!(value.len() < 0x80, "test values stay in the short form");
        v.push(value.len() as u8);
        v.extend_from_slice(value);
        v
    }

    fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
        tlv(0x30, &parts.concat())
    }

    /// A bit string with the given bit numbers set.
    fn bits(set: &[u32]) -> Vec<u8> {
        let highest = set.iter().copied().max().unwrap_or(0) as usize;
        let bytes = highest / 8 + 1;
        let mut data = vec![0u8; bytes];
        for &bit in set {
            data[bit as usize / 8] |= 0x80 >> (bit % 8);
        }
        let unused = (bytes * 8 - (highest + 1)) as u8;
        let mut v = vec![unused];
        v.extend_from_slice(&data);
        tlv(0x03, &v)
    }

    /// Build a PKIMessage with the given body tag and optional status info.
    fn message(body_tag: u8, status: Option<(u8, Vec<u32>)>) -> Vec<u8> {
        // The header carries a context-tagged member of its own, which a search
        // for the body would find first.
        let header = seq(&[tlv(0x02, &[0x02]), tlv(0xA0, &tlv(0x04, &[0xAA]))]);
        let body_content = match status {
            Some((code, failures)) => {
                let mut parts = vec![tlv(0x02, &[code])];
                if !failures.is_empty() {
                    parts.push(bits(&failures));
                }
                seq(&[seq(&parts)])
            }
            None => seq(&[]),
        };
        let body = tlv(0xA0 | body_tag, &body_content[2..]);
        seq(&[header, body])
    }

    /// The reason this dissector exists: an enrolment that fails leaves a
    /// device with no identity, and the reason decides the fix.
    #[test]
    fn an_error_says_which_reason_it_was() {
        // Error body, rejected, badTime.
        let r = dissect_cmp(None, None, 40000, 829, &message(23, Some((2, vec![3]))));
        assert_eq!(r.protocol, Protocol::Cmp);
        assert_eq!(
            r.summary,
            "CMP error — rejected: bad time — the device's clock is wrong"
        );
    }

    /// The reasons need entirely different fixes, so they must be told apart.
    #[test]
    fn the_failure_reasons_are_distinguished() {
        let reason = |bit: u32| describe(&message(23, Some((2, vec![bit]))));
        assert!(reason(1).contains("signature did not verify"));
        assert!(reason(9).contains("proof of possession"));
        assert!(reason(20).contains("signer not trusted"));
        assert!(reason(24).contains("CA is not accepting requests"));
    }

    /// Several reasons can be set at once, and reporting only the first would
    /// lose the rest — which is why they arrive as a bit string.
    #[test]
    fn several_reasons_at_once_are_all_reported() {
        let summary = describe(&message(23, Some((2, vec![3, 20]))));
        assert!(summary.contains("bad time"), "{summary}");
        assert!(summary.contains("signer not trusted"), "{summary}");
    }

    /// An acceptance must not read as a failure.
    #[test]
    fn an_acceptance_is_not_a_rejection() {
        let ok = describe(&message(1, Some((0, vec![]))));
        assert_eq!(ok, "CMP initialisation response — accepted");
        assert!(!ok.contains("reject"), "{ok}");
    }

    /// The enrolment lifecycle is readable message by message.
    #[test]
    fn the_lifecycle_messages_are_named() {
        assert!(describe(&message(0, None)).contains("initialisation request"));
        assert!(describe(&message(7, None)).contains("key update request"));
        assert!(describe(&message(11, None)).contains("revocation request"));
        assert!(describe(&message(24, None)).contains("certificate confirmation"));
    }

    /// The body is taken by position, not by searching for a context tag.
    ///
    /// This test exists in this shape because the first version of it proved
    /// nothing: swapping the positional read for a search broke no test at all.
    /// The comment it was guarding was also wrong — it blamed the header's
    /// nonce, but the header is a SEQUENCE so its tags are nested out of reach.
    ///
    /// The real hazard is `protection`, which follows the body and is `[0]` —
    /// the same tag as `ir`. A message whose body is missing must not be
    /// reported as an initialisation request that nobody sent.
    #[test]
    fn a_message_without_a_body_is_not_read_as_its_protection() {
        let header = seq(&[tlv(0x02, &[0x02])]);
        // Real CMP protection is `[0] IMPLICIT BIT STRING`: primitive, so 0x80.
        let protection = tlv(0x80, &[0xAA, 0xBB]);
        let no_body = seq(&[header, protection]);
        let summary = describe(&no_body);
        assert!(
            !summary.contains("initialisation request"),
            "the protection was read as an ir body: {summary}"
        );
    }

    /// And with a body present, it is the body that is reported.
    #[test]
    fn the_body_is_found_by_position() {
        let summary = describe(&message(23, Some((2, vec![3]))));
        assert!(summary.starts_with("CMP error"), "{summary}");
    }

    /// A body tag outside the standard keeps its number.
    #[test]
    fn an_unassigned_body_keeps_its_number() {
        assert_eq!(describe(&message(30, None)), "CMP (body 30)");
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "CMP (not a PKIMessage)");
        assert_eq!(describe(&[0x30]), "CMP (not a PKIMessage)");
        // A message with a header and no body.
        assert_eq!(describe(&seq(&[seq(&[])])), "CMP");
        assert_eq!(describe(&[0xFF; 8]), "CMP (not a PKIMessage)");
    }

    /// The guard is weak on its own, which is why the caller only applies it on
    /// the assigned port or a matching content type.
    #[test]
    fn recognition_needs_a_sequence_of_sequences() {
        assert!(looks_like_cmp(&message(0, None)));
        assert!(!looks_like_cmp(&tlv(0x30, &tlv(0x02, &[1]))));
        assert!(!looks_like_cmp(b"GET / HTTP/1.1\r\n"));
        assert!(!looks_like_cmp(&[]));
        assert!(is_cmp_type("application/pkixcmp"));
        assert!(!is_cmp_type("application/json"));
    }
}
