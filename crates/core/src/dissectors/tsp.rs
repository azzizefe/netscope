// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! RFC 3161 timestamping — proving a document existed before a given moment.
//!
//! A timestamp authority signs a hash together with the current time, which is
//! what makes a signature outlive its signing certificate. Code signing, legal
//! archives, invoices and long-term document retention all depend on it: the
//! signature stays verifiable years later because a trusted third party
//! attested to when it was made.
//!
//! That dependency is why a refusal is worth catching. A build that cannot
//! reach its timestamp authority produces a signature that verifies today and
//! stops verifying the day the signing certificate expires — and the failure
//! happens at build time, quietly, on a service nobody monitors.
//!
//! ## What a refusal says
//!
//! The response carries a status and a bit string of reasons, the same
//! structure CMP uses (see [`super::pkix`]) with its own meanings:
//!
//! * **timeNotAvailable** — the authority does not currently have a trusted
//!   time source. It is refusing rather than signing a time it cannot stand
//!   behind, which is the correct behaviour and the least obvious one.
//! * **unacceptedPolicy** — the client asked for a policy the authority does
//!   not offer, which is a configuration mismatch rather than an outage.
//! * **badAlg** — the hash algorithm was refused, usually a client still asking
//!   for one that has been withdrawn.
//!
//! Reached through [`super::http_body`]: timestamping runs over HTTP with its
//! own content types, so nothing sees it without looking past the headers.

use std::net::IpAddr;

use crate::models::Protocol;

use super::{pkix, DissectedResult};

/// The two content types RFC 3161 assigns.
pub(crate) fn is_query_type(content_type: &str) -> bool {
    content_type == "application/timestamp-query"
}
pub(crate) fn is_reply_type(content_type: &str) -> bool {
    content_type == "application/timestamp-reply"
}

/// Reason bits, in the order RFC 3161 defines them.
const FAILURES: &[(u32, &str)] = &[
    (0, "bad algorithm"),
    (2, "bad request"),
    (5, "bad data format"),
    (14, "no trusted time source available"),
    (15, "policy not accepted"),
    (16, "extension not accepted"),
    (17, "no additional information available"),
    (25, "system failure"),
];

/// Dissect an RFC 3161 message from an HTTP body.
pub fn dissect_tsp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    body: &[u8],
    is_reply: bool,
) -> DissectedResult {
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Tsp,
        summary: if is_reply {
            describe_reply(body)
        } else {
            "timestamp request".to_string()
        },
    }
}

fn describe_reply(body: &[u8]) -> String {
    // TimeStampResp ::= SEQUENCE {
    //   status          PKIStatusInfo,
    //   timeStampToken  TimeStampToken OPTIONAL }
    //
    // The status is the first member, so the whole response is a status info
    // with a token after it — which is exactly what `pkix::parse` reads.
    let Some(outer) = super::der::read(body).filter(|t| t.tag == 0x30) else {
        return "timestamp response".to_string();
    };
    let Some(parsed) = pkix::parse(outer.value, FAILURES) else {
        return "timestamp response".to_string();
    };

    // Zero is "granted" here, where CMP calls the same value "accepted".
    let outcome = match parsed.status {
        0 => "granted".to_string(),
        other => match pkix::status_name(other) {
            Some(name) => name.to_string(),
            None => format!("status {other}"),
        },
    };

    // A granted response carries the token; a refusal does not, and saying so
    // separates "signed" from "answered". The token is the member *after* the
    // status — skipping that first member matters, because the status info is
    // itself a SEQUENCE and counting it makes every response look tokenised.
    let token = super::der::children(outer.value).nth(1).is_some();

    // The outcome word has exactly one source, so a wrong mapping shows up in
    // every summary rather than only the ones that quote it.
    let detail = match (parsed.reasons.is_empty(), parsed.status, token) {
        (false, _, _) => format!(": {}", parsed.reasons.join(", ")),
        (true, 0, true) => ", token issued".to_string(),
        // A grant with nothing attached is not the same as a grant.
        (true, 0, false) => ", but no token".to_string(),
        _ => String::new(),
    };
    format!("timestamp response — {outcome}{detail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut v = vec![tag, value.len() as u8];
        v.extend_from_slice(value);
        v
    }

    /// Build a TimeStampResp with the given status, reasons and token.
    fn reply(status: u8, set: &[u32], token: bool) -> Vec<u8> {
        let mut info = tlv(0x02, &[status]);
        if !set.is_empty() {
            let highest = set.iter().copied().max().unwrap_or(0) as usize;
            let bytes = highest / 8 + 1;
            let mut data = vec![0u8; bytes];
            for &bit in set {
                data[bit as usize / 8] |= 0x80 >> (bit % 8);
            }
            let mut value = vec![(bytes * 8 - (highest + 1)) as u8];
            value.extend_from_slice(&data);
            info.extend_from_slice(&tlv(0x03, &value));
        }
        let mut parts = tlv(0x30, &info);
        if token {
            // A ContentInfo, which is a SEQUENCE with content in it.
            parts.extend_from_slice(&tlv(0x30, &tlv(0x06, &[0x2A, 0x86])));
        }
        tlv(0x30, &parts)
    }

    /// The reason this dissector exists: a refusal here breaks a signature
    /// years later, and it happens on a service nobody watches.
    #[test]
    fn a_refusal_says_why() {
        let r = dissect_tsp(None, None, 80, 40000, &reply(2, &[14], false), true);
        assert_eq!(r.protocol, Protocol::Tsp);
        assert_eq!(
            r.summary,
            "timestamp response — rejected: no trusted time source available"
        );
    }

    /// The reasons mean different things — one is an outage, one is a
    /// configuration mismatch, one is an obsolete client.
    #[test]
    fn the_reasons_are_distinguished() {
        assert!(describe_reply(&reply(2, &[15], false)).contains("policy not accepted"));
        assert!(describe_reply(&reply(2, &[0], false)).contains("bad algorithm"));
        assert!(describe_reply(&reply(2, &[25], false)).contains("system failure"));
    }

    /// A granted response with a token is the success case, and "granted" with
    /// no token is not the same thing.
    #[test]
    fn a_grant_is_distinguished_from_a_grant_without_a_token() {
        assert_eq!(
            describe_reply(&reply(0, &[], true)),
            "timestamp response — granted, token issued"
        );
        assert_eq!(
            describe_reply(&reply(0, &[], false)),
            "timestamp response — granted, but no token"
        );
    }

    /// Zero means "granted" here and "accepted" in CMP, which is why the
    /// shared parser leaves that word to each protocol.
    #[test]
    fn zero_reads_as_granted_not_accepted() {
        let summary = describe_reply(&reply(0, &[], true));
        assert!(summary.contains("granted"), "{summary}");
        assert!(!summary.contains("accepted"), "{summary}");
    }

    /// A request has no status to read; only the reply carries one.
    #[test]
    fn a_query_and_a_reply_are_told_apart_by_content_type() {
        assert!(is_query_type("application/timestamp-query"));
        assert!(is_reply_type("application/timestamp-reply"));
        assert!(!is_query_type("application/timestamp-reply"));
        assert!(!is_reply_type("application/json"));

        let q = dissect_tsp(None, None, 40000, 80, &[0x30, 0x03], false);
        assert_eq!(q.summary, "timestamp request");
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe_reply(&[]), "timestamp response");
        assert_eq!(describe_reply(&[0x30]), "timestamp response");
        // A response whose status info is unreadable.
        assert_eq!(
            describe_reply(&tlv(0x30, &tlv(0x04, &[1]))),
            "timestamp response"
        );
        assert_eq!(describe_reply(&[0xFF; 8]), "timestamp response");
    }
}
