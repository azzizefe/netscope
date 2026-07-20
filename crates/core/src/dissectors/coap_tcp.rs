// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! CoAP over TCP (RFC 8323).
//!
//! CoAP was designed for UDP, where its own message ids and acknowledgements
//! provide the reliability. Over TCP all of that is redundant, so RFC 8323
//! defines a different framing: no message id, no message type, and a
//! variable-length length field in front instead. The codes and options are the
//! same, but a UDP CoAP parser reading a TCP stream sees nothing it recognises,
//! which is why this needs its own path.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Method and response codes, written the way CoAP presents them: a class and a
/// detail, so 2.05 is "Content" and 4.04 is "Not Found" (RFC 7252 §12.1).
fn code_name(code: u8) -> Option<&'static str> {
    Some(match code {
        0x00 => "empty",
        0x01 => "GET",
        0x02 => "POST",
        0x03 => "PUT",
        0x04 => "DELETE",
        0x05 => "FETCH",
        0x06 => "PATCH",
        0x07 => "iPATCH",
        0x41 => "2.01 Created",
        0x42 => "2.02 Deleted",
        0x43 => "2.03 Valid",
        0x44 => "2.04 Changed",
        0x45 => "2.05 Content",
        0x5F => "2.31 Continue",
        0x80 => "4.00 Bad Request",
        0x81 => "4.01 Unauthorized",
        0x82 => "4.02 Bad Option",
        0x83 => "4.03 Forbidden",
        0x84 => "4.04 Not Found",
        0x85 => "4.05 Method Not Allowed",
        0x86 => "4.06 Not Acceptable",
        0x8C => "4.12 Precondition Failed",
        0x8D => "4.13 Request Entity Too Large",
        0x8F => "4.15 Unsupported Content-Format",
        0xA0 => "5.00 Internal Server Error",
        0xA1 => "5.01 Not Implemented",
        0xA2 => "5.02 Bad Gateway",
        0xA3 => "5.03 Service Unavailable",
        0xA4 => "5.04 Gateway Timeout",
        0xA5 => "5.05 Proxying Not Supported",
        // The signalling codes are unique to the TCP form: they negotiate the
        // connection rather than carrying a resource operation.
        0xE1 => "7.01 CSM (capabilities)",
        0xE2 => "7.02 Ping",
        0xE3 => "7.03 Pong",
        0xE4 => "7.04 Release",
        0xE5 => "7.05 Abort",
        _ => return None,
    })
}

/// The first nibble of the first byte gives the length, or says how many extra
/// bytes hold it (RFC 8323 §3.2).
const LEN_EXTENDED_8: u8 = 13;
const LEN_EXTENDED_16: u8 = 14;
const LEN_EXTENDED_32: u8 = 15;

/// Where the code sits, given the length nibble.
fn code_offset(len_nibble: u8) -> usize {
    match len_nibble {
        LEN_EXTENDED_8 => 2,
        LEN_EXTENDED_16 => 3,
        LEN_EXTENDED_32 => 5,
        _ => 1,
    }
}

fn parse(payload: &[u8]) -> Option<String> {
    let first = *payload.first()?;
    let len_nibble = first >> 4;
    let token_len = first & 0x0F;
    // Token lengths above 8 are reserved and never appear in a real message.
    if token_len > 8 {
        return None;
    }
    let code = *payload.get(code_offset(len_nibble))?;
    let name = code_name(code)?;
    Some(format!("CoAP/TCP {name}"))
}

/// Dissect a CoAP-over-TCP message (TCP 5683, and 5684 for the TLS form).
///
/// Recognition is by port alone, deliberately. The framing has no magic and no
/// version field, so almost anything can be read as a plausible header: an HTTP
/// request beginning `GET ` parses as a valid length nibble followed by the
/// code for "2.05 Content". A structural check here would take traffic that
/// belongs to other dissectors.
pub fn dissect_coap_tcp(
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
        protocol: Protocol::CoapTcp,
        summary: parse(payload)
            .unwrap_or_else(|| format!("CoAP/TCP ({})", super::bytes(payload.len() as u64))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a short-form message: one byte of length and token length, then
    /// the code.
    fn short(len: u8, token_len: u8, code: u8) -> Vec<u8> {
        let mut p = vec![(len << 4) | token_len, code];
        p.extend_from_slice(&[0u8; 4]);
        p
    }

    #[test]
    fn methods_and_responses_are_named() {
        let r = dissect_coap_tcp(None, None, 40000, 5683, &short(4, 0, 0x01));
        assert_eq!(r.protocol, Protocol::CoapTcp);
        assert_eq!(r.summary, "CoAP/TCP GET");
        assert_eq!(
            dissect_coap_tcp(None, None, 5683, 1, &short(4, 0, 0x45)).summary,
            "CoAP/TCP 2.05 Content"
        );
        assert_eq!(
            dissect_coap_tcp(None, None, 5683, 1, &short(4, 0, 0x84)).summary,
            "CoAP/TCP 4.04 Not Found"
        );
    }

    /// The signalling codes exist only in the TCP form and negotiate the
    /// connection rather than acting on a resource.
    #[test]
    fn signalling_codes_are_named() {
        assert_eq!(
            dissect_coap_tcp(None, None, 1, 5683, &short(4, 0, 0xE1)).summary,
            "CoAP/TCP 7.01 CSM (capabilities)"
        );
        assert_eq!(
            dissect_coap_tcp(None, None, 1, 5683, &short(4, 0, 0xE2)).summary,
            "CoAP/TCP 7.02 Ping"
        );
    }

    /// The length field is variable, so the code is not at a fixed offset —
    /// reading byte 1 regardless would pick up part of the length instead.
    #[test]
    fn the_code_is_found_past_an_extended_length() {
        // 8-bit extended length: one extra byte before the code.
        let mut p = vec![(LEN_EXTENDED_8 << 4), 200, 0x01];
        p.extend_from_slice(&[0u8; 4]);
        assert_eq!(
            dissect_coap_tcp(None, None, 1, 5683, &p).summary,
            "CoAP/TCP GET"
        );

        // 16-bit extended length: two extra bytes.
        let mut p = vec![(LEN_EXTENDED_16 << 4), 0x10, 0x00, 0x02];
        p.extend_from_slice(&[0u8; 4]);
        assert_eq!(
            dissect_coap_tcp(None, None, 1, 5683, &p).summary,
            "CoAP/TCP POST"
        );

        // 32-bit extended length: four extra bytes.
        let mut p = vec![(LEN_EXTENDED_32 << 4), 0, 0x01, 0x00, 0x00, 0x03];
        p.extend_from_slice(&[0u8; 4]);
        assert_eq!(
            dissect_coap_tcp(None, None, 1, 5683, &p).summary,
            "CoAP/TCP PUT"
        );
    }

    /// A token length above eight is reserved, so a message carrying one is
    /// malformed and reports its size rather than a made-up code.
    #[test]
    fn a_reserved_token_length_is_rejected() {
        assert!(parse(&short(4, 9, 0x01)).is_none());
        assert!(parse(&short(4, 15, 0x01)).is_none());
        assert!(parse(&short(4, 8, 0x01)).is_some());
    }

    /// Why this dissector is reached by port and never by content: the framing
    /// has no magic and no version field, so an ordinary HTTP request parses as
    /// a perfectly valid CoAP header. Anything that sniffed for this shape
    /// would take traffic belonging to other dissectors.
    #[test]
    fn an_http_request_parses_as_a_plausible_coap_header() {
        assert_eq!(
            parse(b"GET / HTTP/1.1\r\n").as_deref(),
            Some("CoAP/TCP 2.05 Content")
        );
    }

    #[test]
    fn unknown_code_reports_the_size() {
        let r = dissect_coap_tcp(None, None, 1, 5683, &short(4, 0, 0x7F));
        assert_eq!(r.summary, "CoAP/TCP (6 bytes)");
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_coap_tcp(None, None, 1, 5683, &[0x40]);
        assert_eq!(r.summary, "CoAP/TCP (1 byte)");
    }
}
