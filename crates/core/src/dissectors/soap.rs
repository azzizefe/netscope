// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! SOAP — the operation hiding inside `POST /`.
//!
//! An enormous amount of device management is SOAP over HTTP, and none of it is
//! visible from the request line. Every call is `POST /onvif/device_service` or
//! `POST /` with a 200 back; what the call actually *did* is an element name in
//! the body. A capture of a camera being reconfigured and one of a camera being
//! polled for its time look identical until the envelope is opened.
//!
//! Two families dominate and both are worth telling apart, which the namespace
//! does:
//!
//! * **ONVIF** — IP cameras. `SetSystemDateAndTime`, `CreateUsers` and
//!   `SetNetworkInterfaces` are the ones that change a camera out from under
//!   whoever is recording from it.
//! * **TR-069 / CWMP** — the protocol an ISP uses to manage the router in a
//!   subscriber's house. `Inform` is the router checking in; `SetParameterValues`
//!   and `Download` are the ACS changing its configuration or pushing firmware.
//!   A `Download` nobody scheduled is worth knowing about.
//!
//! Reached through [`super::http_body`], which finds the body without decoding
//! it — this module only ever looks at the first part of the envelope.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Only the opening of the envelope is examined; a SOAP body can be large and
/// the operation is always near the front.
const SCAN: usize = 4096;

/// Content types that carry a SOAP envelope.
pub(crate) fn is_soap_type(content_type: &str) -> bool {
    matches!(content_type, "application/soap+xml" | "text/xml")
}

/// Which management family this envelope belongs to, from its namespaces.
fn family(envelope: &str) -> Option<&'static str> {
    if envelope.contains("://www.onvif.org/") {
        Some("ONVIF")
    } else if envelope.contains("cwmp-1-") || envelope.contains("urn:dslforum-org:cwmp") {
        Some("TR-069")
    } else {
        None
    }
}

/// Pull the operation name out of the envelope.
///
/// The operation is the first element inside `<soap:Body>`, so the body element
/// is found first and the next tag after it read. Taking the first element in
/// the document instead would return `Envelope`, and taking the first element
/// with a namespace prefix would return whatever the header happens to carry —
/// a security token, usually.
fn operation(envelope: &str) -> Option<&str> {
    let lower = envelope.to_ascii_lowercase();
    // The body element is namespace-prefixed in practice (`soap:Body`,
    // `s:Body`, `env:Body`), so it is found by its local name.
    let body_at = lower
        .match_indices("body")
        .find(|(i, _)| {
            // Preceded by `<` or `<prefix:`, and followed by `>` or whitespace.
            let before = lower[..*i].rfind('<').is_some_and(|lt| {
                let between = &lower[lt + 1..*i];
                between.is_empty() || between.ends_with(':')
            });
            let after = lower[i + 4..]
                .chars()
                .next()
                .is_some_and(|c| c == '>' || c.is_whitespace());
            before && after
        })
        .map(|(i, _)| i)?;

    // The next opening tag after the body element is the operation.
    let rest = &envelope[body_at..];
    let open = rest.find('>')?;
    let after_body = &rest[open + 1..];
    let tag_start = after_body.find('<')?;
    let tag = &after_body[tag_start + 1..];
    // Closing tags and comments are not operations.
    if tag.starts_with('/') || tag.starts_with('!') || tag.starts_with('?') {
        return None;
    }
    let end = tag.find(['>', ' ', '\t', '\r', '\n', '/'])?;
    let name = &tag[..end];
    // Strip the namespace prefix — the local name is the operation.
    let name = name.rsplit(':').next().unwrap_or(name);
    (!name.is_empty()).then_some(name)
}

/// Dissect a SOAP envelope carried in an HTTP body.
pub fn dissect_soap(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    body: &[u8],
) -> DissectedResult {
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Soap,
        summary: describe(body),
    }
}

fn describe(body: &[u8]) -> String {
    let head = &body[..body.len().min(SCAN)];
    let Ok(envelope) = std::str::from_utf8(head)
        .or_else(|e| std::str::from_utf8(&head[..e.valid_up_to()]).map_err(|_| e))
    else {
        return "SOAP".to_string();
    };

    let what = operation(envelope);
    // A Fault is the answer whatever the family, and it carries its own reason.
    if what.is_some_and(|op| op.eq_ignore_ascii_case("fault")) {
        let reason = fault_reason(envelope);
        return match reason {
            Some(text) => format!("SOAP Fault — {}", super::truncate(text, 60)),
            None => "SOAP Fault".to_string(),
        };
    }

    match (family(envelope), what) {
        (Some(family), Some(op)) => format!("{family} {}", super::truncate(op, 60)),
        (Some(family), None) => format!("{family} request"),
        (None, Some(op)) => format!("SOAP {}", super::truncate(op, 60)),
        (None, None) => "SOAP".to_string(),
    }
}

/// The human-readable half of a fault, which is what says why it failed.
fn fault_reason(envelope: &str) -> Option<&str> {
    for tag in ["faultstring", "Text", "Value"] {
        let open = format!("<{tag}");
        if let Some(at) = envelope.find(&open) {
            let rest = &envelope[at..];
            let content = rest.find('>')?;
            let text = &rest[content + 1..];
            let end = text.find('<')?;
            let text = text[..end].trim();
            if !text.is_empty() {
                return Some(text);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(namespace: &str, body_inner: &str) -> Vec<u8> {
        format!(
            "<?xml version=\"1.0\"?>\
             <soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" {namespace}>\
             <soap:Header><wsse:Security>token</wsse:Security></soap:Header>\
             <soap:Body>{body_inner}</soap:Body>\
             </soap:Envelope>"
        )
        .into_bytes()
    }

    /// The reason this dissector exists: every one of these is `POST /` with a
    /// 200 back, and the operation is the only thing that differs.
    #[test]
    fn an_onvif_operation_is_named() {
        let p = envelope(
            "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\"",
            "<tds:SetSystemDateAndTime><tds:DateTimeType>Manual</tds:DateTimeType></tds:SetSystemDateAndTime>",
        );
        let r = dissect_soap(None, None, 40000, 80, &p);
        assert_eq!(r.protocol, Protocol::Soap);
        assert_eq!(r.summary, "ONVIF SetSystemDateAndTime");
    }

    /// TR-069 is the other family worth telling apart, and a firmware push
    /// nobody scheduled is the thing to catch.
    #[test]
    fn a_tr069_operation_is_named() {
        let p = envelope(
            "xmlns:cwmp=\"urn:dslforum-org:cwmp-1-0\"",
            "<cwmp:Download><CommandKey>x</CommandKey></cwmp:Download>",
        );
        assert_eq!(describe(&p), "TR-069 Download");

        let inform = envelope(
            "xmlns:cwmp=\"urn:dslforum-org:cwmp-1-2\"",
            "<cwmp:Inform><DeviceId/></cwmp:Inform>",
        );
        assert_eq!(describe(&inform), "TR-069 Inform");
    }

    /// The operation is the first element *inside the body*. Taking the first
    /// element in the document gives `Envelope`; taking the first prefixed
    /// element gives whatever the header carries — a security token, here.
    #[test]
    fn the_operation_comes_from_inside_the_body_not_the_header() {
        let p = envelope(
            "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\"",
            "<tds:GetSystemDateAndTime/>",
        );
        let summary = describe(&p);
        assert_eq!(summary, "ONVIF GetSystemDateAndTime");
        assert!(!summary.contains("Envelope"), "{summary}");
        assert!(!summary.contains("Security"), "{summary}");
    }

    /// A fault is the answer whatever the family, and carries its own reason.
    #[test]
    fn a_fault_reports_why() {
        let p = envelope(
            "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\"",
            "<soap:Fault><faultstring>Sender not authorized</faultstring></soap:Fault>",
        );
        assert_eq!(describe(&p), "SOAP Fault — Sender not authorized");
    }

    /// An envelope from neither family is still readable.
    #[test]
    fn an_unfamiliar_namespace_still_names_the_operation() {
        let p = envelope("xmlns:x=\"urn:example\"", "<x:DoTheThing/>");
        assert_eq!(describe(&p), "SOAP DoTheThing");
    }

    /// Only the content types that actually carry an envelope are claimed.
    #[test]
    fn only_soap_content_types_are_claimed() {
        assert!(is_soap_type("application/soap+xml"));
        assert!(is_soap_type("text/xml"));
        assert!(!is_soap_type("application/json"));
        assert!(!is_soap_type("application/xml"));
        assert!(!is_soap_type(""));
    }

    /// End to end through the real HTTP dissector — this is what E1 was for.
    /// Without the body being reached, every one of these reads as
    /// "HTTP POST /onvif/device_service" and nothing more.
    #[test]
    fn an_onvif_call_is_read_through_the_http_dissector() {
        let body = envelope(
            "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\"",
            "<tds:CreateUsers><tds:User/></tds:CreateUsers>",
        );
        let mut request = b"POST /onvif/device_service HTTP/1.1\r\nHost: cam\r\n\
            Content-Type: application/soap+xml; charset=utf-8\r\n\r\n"
            .to_vec();
        request.extend_from_slice(&body);

        let r = super::super::http::dissect_http(None, None, 40000, 80, &request);
        assert_eq!(r.protocol, Protocol::Soap);
        assert_eq!(r.summary, "HTTP · ONVIF CreateUsers");
    }

    /// An ordinary API call must still read as HTTP — only content types that
    /// are actually claimed take the body path.
    #[test]
    fn an_ordinary_body_still_reads_as_http() {
        let request = b"POST /api/data HTTP/1.1\r\n\
            Content-Type: application/json\r\n\r\n{\"k\":1}";
        let r = super::super::http::dissect_http(None, None, 40000, 80, request);
        assert_eq!(r.protocol, Protocol::Http);
        assert!(
            r.summary.starts_with("HTTP POST /api/data"),
            "{}",
            r.summary
        );
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(b""), "SOAP");
        assert_eq!(describe(b"<soap:Envelope>"), "SOAP");
        // A body element with nothing after it.
        assert_eq!(describe(b"<soap:Body>"), "SOAP");
        // A body containing only a closing tag.
        assert_eq!(describe(b"<soap:Body></soap:Body>"), "SOAP");
        // Not XML at all.
        assert_eq!(describe(&[0xFF, 0xFE, 0xFD]), "SOAP");
    }
}
