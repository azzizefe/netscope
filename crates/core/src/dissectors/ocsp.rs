// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! OCSP — asking whether a certificate has been revoked (RFC 6960).
//!
//! When a client is handed a certificate it can ask the issuing CA whether that
//! certificate is still good. The answer decides whether a TLS connection is
//! allowed to proceed, so an OCSP exchange that goes wrong takes working
//! connections down with it — and it does so from a *different host* than the
//! one the user was connecting to, which is what makes it hard to find.
//!
//! ## The thing that has to be read correctly
//!
//! An OCSP response carries **two** statuses and they mean opposite things.
//!
//! The outer one is transport-level: did the responder manage to answer at all
//! (`successful`, `tryLater`, `unauthorized`…). The inner one — buried inside
//! the signed `BasicOCSPResponse`, about seven levels down — is the actual
//! verdict on the certificate: **good**, **revoked**, or **unknown**.
//!
//! Reading only the outer one is worse than reading nothing, because a revoked
//! certificate is reported inside a response whose transport status is
//! `successful`. "OCSP successful" next to a browser refusing to load a page is
//! exactly the confusion this dissector exists to remove.
//!
//! That depth is why OCSP sat in the declined register: reaching it needs both
//! the HTTP body (E1) and a DER walk that does not lose its place (E8).

use std::net::IpAddr;

use crate::models::Protocol;

use super::{der, DissectedResult};

/// Content types RFC 6960 assigns to the two directions.
pub(crate) fn is_request_type(content_type: &str) -> bool {
    content_type == "application/ocsp-request"
}
pub(crate) fn is_response_type(content_type: &str) -> bool {
    content_type == "application/ocsp-response"
}

/// The transport-level status — whether an answer was produced at all.
fn response_status(status: u64) -> &'static str {
    match status {
        0 => "successful",
        1 => "malformed request",
        2 => "internal error",
        3 => "try later",
        5 => "signature required",
        6 => "unauthorised",
        _ => "unassigned status",
    }
}

/// Dissect an OCSP message from an HTTP body.
pub fn dissect_ocsp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    body: &[u8],
    is_response: bool,
) -> DissectedResult {
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ocsp,
        summary: if is_response {
            describe_response(body)
        } else {
            describe_request(body)
        },
    }
}

fn describe_request(body: &[u8]) -> String {
    // OCSPRequest ::= SEQUENCE { tbsRequest TBSRequest, ... }
    // TBSRequest  ::= SEQUENCE { ..., requestList SEQUENCE OF Request, ... }
    let count = der::read(body)
        .filter(|t| t.is_constructed())
        .and_then(|outer| der::read(outer.value))
        .map(|tbs| {
            // The request list is the first SEQUENCE inside TBSRequest that is
            // not one of the optional context-tagged members ahead of it.
            der::children(tbs.value)
                .find(|t| t.context_tag().is_none() && t.is_constructed())
                .map(|list| der::children(list.value).count())
                .unwrap_or(0)
        })
        .unwrap_or(0);

    match count {
        0 => "OCSP request".to_string(),
        1 => "OCSP request — 1 certificate".to_string(),
        n => format!("OCSP request — {n} certificates"),
    }
}

fn describe_response(body: &[u8]) -> String {
    // OCSPResponse ::= SEQUENCE {
    //   responseStatus  OCSPResponseStatus (ENUMERATED),
    //   responseBytes   [0] EXPLICIT ResponseBytes OPTIONAL }
    let Some(outer) = der::read(body).filter(|t| t.is_constructed()) else {
        return "OCSP response".to_string();
    };
    let Some(status) = der::find(outer.value, 0x0A).and_then(|t| der::uint(t.value)) else {
        return "OCSP response".to_string();
    };

    // A transport-level failure has no certificate verdict inside it at all.
    if status != 0 {
        return format!("OCSP response — {} (no verdict)", response_status(status));
    }

    match certificate_status(outer.value) {
        Some(verdict) => format!("OCSP response — certificate {verdict}"),
        // Successful transport, but the verdict could not be reached. Saying
        // "successful" alone would be read as "the certificate is fine", which
        // is precisely the wrong conclusion.
        None => "OCSP response — successful, verdict not readable".to_string(),
    }
}

/// Walk down to the certificate's actual status.
///
/// The path is long and every step is a walk rather than a search, because the
/// structures on the way down contain SEQUENCEs and OCTET STRINGs that look
/// exactly like the ones being looked for:
///
/// ```text
/// responseBytes [0] → ResponseBytes SEQUENCE
///   responseType  OID
///   response      OCTET STRING  ← BasicOCSPResponse, DER inside DER
///     BasicOCSPResponse SEQUENCE
///       tbsResponseData SEQUENCE
///         (version [0], responderID [1]/[2], producedAt, …)
///         responses SEQUENCE OF SingleResponse
///           SingleResponse SEQUENCE
///             certID    SEQUENCE   ← also a SEQUENCE; skipping it is the point
///             certStatus CHOICE    ← [0] good, [1] revoked, [2] unknown
/// ```
fn certificate_status(outer: &[u8]) -> Option<&'static str> {
    // [0] EXPLICIT ResponseBytes.
    let response_bytes = der::children(outer).find(|t| t.context_tag() == Some(0))?;
    let bytes_seq = der::read(response_bytes.value)?;

    // Inside: the response type OID, then the OCTET STRING holding the real
    // response. Taking the first OCTET STRING would be right here, but taking
    // the first *constructed* thing would land on the OID's container.
    let response = der::find(bytes_seq.value, 0x04)?;

    // The OCTET STRING's contents are themselves DER.
    let basic = der::read(response.value)?;
    let tbs = der::read(basic.value)?;

    // Within tbsResponseData the optional version and the responder identity
    // come first and are context-tagged, and producedAt is a GeneralizedTime.
    // The response list is the last plain constructed member, since all of
    // those precede it.
    let responses = der::children(tbs.value)
        .filter(|t| t.context_tag().is_none() && t.is_constructed())
        .last()?;

    let single = der::read(responses.value)?;

    // certID is a SEQUENCE and comes first; the status is what follows it.
    // Searching for a context tag instead would find the ones inside certID.
    let mut fields = der::children(single.value);
    let _cert_id = fields.next()?;
    let status = fields.next()?;

    Some(match status.context_tag()? {
        0 => "good",
        1 => "REVOKED",
        2 => "unknown to the responder",
        _ => return None,
    })
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

    /// Build an OCSP response carrying the given certificate status choice.
    fn response(transport_status: u8, cert_status: Option<u8>) -> Vec<u8> {
        let mut parts = vec![tlv(0x0A, &[transport_status])];
        if let Some(choice) = cert_status {
            // SingleResponse: certID SEQUENCE, then the status CHOICE.
            let single = seq(&[
                seq(&[tlv(0x06, &[0x2B, 0x0E]), tlv(0x04, &[0xAA; 4])]), // certID
                tlv(0x80 | choice, &[]),                                 // certStatus
            ]);
            let responses = seq(&[single]);
            let tbs = seq(&[
                tlv(0xA0, &tlv(0x02, &[0x00])), // version [0]
                tlv(0xA1, &tlv(0x04, &[0xBB])), // responderID [1]
                tlv(0x18, b"20260721000000Z"),  // producedAt
                responses,
            ]);
            let basic = seq(&[tbs, seq(&[]), tlv(0x03, &[0x00, 0xCC])]);
            let response_bytes = seq(&[tlv(0x06, &[0x2B, 0x06]), tlv(0x04, &basic)]);
            parts.push(tlv(0xA0, &response_bytes));
        }
        seq(&parts)
    }

    /// The reason this dissector exists: a revoked certificate arrives inside a
    /// response whose transport status is "successful". Reading only the outer
    /// status reports the opposite of the truth.
    #[test]
    fn a_revoked_certificate_is_reported_not_the_transport_status() {
        let r = dissect_ocsp(None, None, 80, 40000, &response(0, Some(1)), true);
        assert_eq!(r.protocol, Protocol::Ocsp);
        assert_eq!(r.summary, "OCSP response — certificate REVOKED");
        assert!(!r.summary.contains("successful"), "{}", r.summary);
    }

    /// The three verdicts are what the connection actually turns on.
    #[test]
    fn the_certificate_verdicts_are_distinguished() {
        assert_eq!(
            describe_response(&response(0, Some(0))),
            "OCSP response — certificate good"
        );
        assert_eq!(
            describe_response(&response(0, Some(2))),
            "OCSP response — certificate unknown to the responder"
        );
    }

    /// A transport-level failure carries no verdict at all, and must not be
    /// reported as though the certificate were fine.
    #[test]
    fn a_transport_failure_says_there_is_no_verdict() {
        assert_eq!(
            describe_response(&response(3, None)),
            "OCSP response — try later (no verdict)"
        );
        assert_eq!(
            describe_response(&response(6, None)),
            "OCSP response — unauthorised (no verdict)"
        );
    }

    /// Successful transport with an unreadable verdict must not read as "good".
    /// This is the failure mode that made a shallow implementation worthless.
    #[test]
    fn a_successful_transport_without_a_readable_verdict_says_so() {
        let summary = describe_response(&response(0, None));
        assert_eq!(summary, "OCSP response — successful, verdict not readable");
        assert!(!summary.contains("good"), "{summary}");
    }

    /// The status follows certID, which is itself a SEQUENCE containing an
    /// OCTET STRING. Searching for the first context tag would find one inside
    /// certID rather than the verdict.
    #[test]
    fn the_verdict_is_found_after_certid_not_inside_it() {
        // certID here contains a context-tagged member of its own.
        let single = seq(&[
            seq(&[tlv(0xA0, &[0x01]), tlv(0x04, &[0xAA; 4])]), // certID with [0] inside
            tlv(0x81, &[]),                                    // the real status: revoked
        ]);
        let responses = seq(&[single]);
        let tbs = seq(&[tlv(0x18, b"20260721000000Z"), responses]);
        let basic = seq(&[tbs]);
        let response_bytes = seq(&[tlv(0x06, &[0x2B]), tlv(0x04, &basic)]);
        let outer = seq(&[tlv(0x0A, &[0x00]), tlv(0xA0, &response_bytes)]);

        assert_eq!(
            describe_response(&outer),
            "OCSP response — certificate REVOKED"
        );
    }

    /// A request says how many certificates are being asked about.
    #[test]
    fn a_request_counts_the_certificates_asked_about() {
        let one = seq(&[seq(&[tlv(0x06, &[0x2B]), tlv(0x04, &[0x01])])]);
        let tbs = seq(&[one]);
        assert_eq!(
            describe_request(&seq(&[tbs])),
            "OCSP request — 1 certificate"
        );

        let two = seq(&[
            seq(&[tlv(0x06, &[0x2B]), tlv(0x04, &[0x01])]),
            seq(&[tlv(0x06, &[0x2B]), tlv(0x04, &[0x02])]),
        ]);
        assert_eq!(
            describe_request(&seq(&[seq(&[two])])),
            "OCSP request — 2 certificates"
        );
    }

    /// Only the two assigned content types are claimed.
    #[test]
    fn only_the_ocsp_content_types_are_claimed() {
        assert!(is_request_type("application/ocsp-request"));
        assert!(is_response_type("application/ocsp-response"));
        assert!(!is_request_type("application/ocsp-response"));
        assert!(!is_response_type("application/json"));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe_response(&[]), "OCSP response");
        assert_eq!(describe_response(&[0x30]), "OCSP response");
        assert_eq!(describe_request(&[]), "OCSP request");
        // A SEQUENCE promising more than it holds.
        assert_eq!(describe_response(&[0x30, 0x7F, 0x0A]), "OCSP response");
        // Not DER at all.
        assert_eq!(describe_response(&[0xFF; 8]), "OCSP response");
    }
}
