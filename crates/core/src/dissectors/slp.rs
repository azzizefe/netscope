// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// SLP function ids (RFC 2608 §8).
fn function_name(f: u8) -> Option<&'static str> {
    Some(match f {
        1 => "Service Request",
        2 => "Service Reply",
        3 => "Service Registration",
        4 => "Service Deregister",
        5 => "Service Acknowledge",
        6 => "Attribute Request",
        7 => "Attribute Reply",
        8 => "DA Advertisement",
        9 => "Service Type Request",
        10 => "Service Type Reply",
        11 => "SA Advertisement",
        _ => return None,
    })
}

/// Version, function, length, flags, extension offset, transaction id and the
/// language tag length — fourteen bytes before the tag itself.
const HEADER_V2: usize = 14;
const VERSION_2: u8 = 2;
/// Version 1 has a different layout; it is recognised but not decoded further.
const VERSION_1: u8 = 1;

/// Dissect an SLP message — the Service Location Protocol, on port 427
/// (RFC 2608).
///
/// SLP lets a machine ask "who on this network offers this service?" without
/// any central directory. It is best known now as the discovery protocol
/// VMware ESXi exposes, where an unauthenticated request could be turned into
/// a large amplified response and, in 2023, into a widely exploited entry
/// point — so seeing it reachable from an untrusted network is worth noticing.
pub fn dissect_slp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary =
        parse(payload).unwrap_or_else(|| format!("SLP ({})", super::bytes(payload.len() as u64)));
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Slp,
        summary,
    }
}

fn parse(payload: &[u8]) -> Option<String> {
    let version = *payload.first()?;
    let function = *payload.get(1)?;
    match version {
        VERSION_2 => {}
        VERSION_1 => return Some("SLP v1 message".to_string()),
        _ => return None,
    }
    let name = function_name(function)?;

    // The declared length is three bytes and covers the whole message, so a
    // value that cannot hold the header means this is not SLP.
    let length = u32::from_be_bytes([0, *payload.get(2)?, *payload.get(3)?, *payload.get(4)?]);
    if (length as usize) < HEADER_V2 {
        return None;
    }
    // A service request names the service type it is looking for, which is the
    // useful part — "who offers VMware management here?" rather than just
    // "someone asked something".
    let service = service_type(payload);
    Some(match service {
        Some(s) => format!("SLP {name} — {}", super::truncate(&s, 40)),
        None => format!("SLP {name}"),
    })
}

/// Read the service type from a request, which follows the language tag.
///
/// The body is a chain of length-prefixed strings; the first two belong to the
/// previous-responder list and the service type respectively.
fn service_type(payload: &[u8]) -> Option<String> {
    let lang_len = u16::from_be_bytes([*payload.get(12)?, *payload.get(13)?]) as usize;
    let mut at = HEADER_V2 + lang_len;
    // The previous-responder list comes first and is usually empty.
    let responders = u16::from_be_bytes([*payload.get(at)?, *payload.get(at + 1)?]) as usize;
    at += 2 + responders;
    let type_len = u16::from_be_bytes([*payload.get(at)?, *payload.get(at + 1)?]) as usize;
    if type_len == 0 || type_len > 128 {
        return None;
    }
    let bytes = payload.get(at + 2..at + 2 + type_len)?;
    let text = std::str::from_utf8(bytes).ok()?;
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an SLP v2 service request looking for `service`.
    fn request(function: u8, service: &str) -> Vec<u8> {
        let lang = b"en";
        let body_len = 2 + lang.len() + 2 + 2 + service.len();
        let total = HEADER_V2 - 2 + body_len;

        let mut p = vec![VERSION_2, function];
        p.extend_from_slice(&(total as u32).to_be_bytes()[1..]); // 3-byte length
        p.extend_from_slice(&0u16.to_be_bytes()); // flags
        p.extend_from_slice(&[0, 0, 0]); // next extension offset
        p.extend_from_slice(&1u16.to_be_bytes()); // transaction id
        p.extend_from_slice(&(lang.len() as u16).to_be_bytes());
        p.extend_from_slice(lang);
        p.extend_from_slice(&0u16.to_be_bytes()); // previous responder list: empty
        p.extend_from_slice(&(service.len() as u16).to_be_bytes());
        p.extend_from_slice(service.as_bytes());
        p
    }

    #[test]
    fn service_request_names_what_is_being_sought() {
        let p = request(1, "service:VMwareInfrastructure");
        let r = dissect_slp(None, None, 40000, 427, &p);
        assert_eq!(r.protocol, Protocol::Slp);
        assert_eq!(
            r.summary,
            "SLP Service Request — service:VMwareInfrastructure"
        );
    }

    #[test]
    fn the_other_functions_are_named() {
        assert!(dissect_slp(None, None, 1, 427, &request(2, "service:x"))
            .summary
            .contains("Service Reply"));
        assert!(dissect_slp(None, None, 1, 427, &request(3, "service:x"))
            .summary
            .contains("Service Registration"));
        assert!(dissect_slp(None, None, 1, 427, &request(8, "service:x"))
            .summary
            .contains("DA Advertisement"));
    }

    /// The language tag sits between the header and the body and varies in
    /// length, so the service type is not at a fixed offset.
    #[test]
    fn service_type_is_found_past_a_variable_language_tag() {
        let mut p = vec![VERSION_2, 1];
        p.extend_from_slice(&40u32.to_be_bytes()[1..]);
        p.extend_from_slice(&0u16.to_be_bytes());
        p.extend_from_slice(&[0, 0, 0]);
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&5u16.to_be_bytes()); // a five-byte language tag
        p.extend_from_slice(b"en-GB");
        p.extend_from_slice(&0u16.to_be_bytes());
        p.extend_from_slice(&7u16.to_be_bytes());
        p.extend_from_slice(b"service");
        assert_eq!(
            dissect_slp(None, None, 1, 427, &p).summary,
            "SLP Service Request — service"
        );
    }

    /// Version 1 is a different layout and is named rather than misread.
    #[test]
    fn version_one_is_recognised_but_not_decoded() {
        let r = dissect_slp(None, None, 1, 427, &[VERSION_1, 1, 0, 0, 0, 0]);
        assert_eq!(r.summary, "SLP v1 message");
    }

    #[test]
    fn foreign_payloads_are_not_claimed() {
        assert!(parse(b"GET / HTTP/1.1").is_none());
        assert!(parse(&[]).is_none());
        // A version we do not know.
        assert!(parse(&[9, 1, 0, 0, 20]).is_none());
        // A length too small to hold the header.
        assert!(parse(&[VERSION_2, 1, 0, 0, 4]).is_none());
    }

    #[test]
    fn request_without_a_readable_service_type_still_names_the_function() {
        let mut p = vec![VERSION_2, 1];
        p.extend_from_slice(&20u32.to_be_bytes()[1..]);
        p.extend_from_slice(&[0u8; 9]);
        assert_eq!(
            dissect_slp(None, None, 1, 427, &p).summary,
            "SLP Service Request"
        );
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_slp(None, None, 1, 427, &[VERSION_2]);
        assert_eq!(r.summary, "SLP (1 byte)");
    }
}
