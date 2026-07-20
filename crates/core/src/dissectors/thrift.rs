// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Apache Thrift — the RPC framing behind HBase, Hive and a good deal of
//! service-to-service traffic that predates gRPC.
//!
//! Thrift's useful property for a capture is that the method name travels in
//! the clear at the front of every call, so a single packet says which
//! operation a service was asked to perform rather than merely that two
//! services talked.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The strict binary protocol marks every message with this version prefix.
const VERSION_MASK: u32 = 0xFFFF_0000;
const VERSION_1: u32 = 0x8001_0000;

/// Message types (Thrift binary protocol specification).
fn message_name(t: u8) -> Option<&'static str> {
    Some(match t {
        1 => "call",
        2 => "reply",
        3 => "exception",
        4 => "oneway",
        _ => return None,
    })
}

/// A method name longer than this is not a name, it is a misparse.
const MAX_NAME: u32 = 256;

/// Parse a strict binary message, returning the type and method name.
fn parse_message(payload: &[u8]) -> Option<(&'static str, String)> {
    let header = u32::from_be_bytes([
        *payload.first()?,
        *payload.get(1)?,
        *payload.get(2)?,
        *payload.get(3)?,
    ]);
    if header & VERSION_MASK != VERSION_1 {
        return None;
    }
    // The message type is the low byte of the same word.
    let name = message_name((header & 0xFF) as u8)?;
    let name_len = u32::from_be_bytes([
        *payload.get(4)?,
        *payload.get(5)?,
        *payload.get(6)?,
        *payload.get(7)?,
    ]);
    if name_len == 0 || name_len > MAX_NAME {
        return None;
    }
    let bytes = payload.get(8..8 + name_len as usize)?;
    // A method name is an identifier; anything else means we are misreading.
    if !bytes.iter().all(|b| b.is_ascii_graphic()) {
        return None;
    }
    Some((name, String::from_utf8_lossy(bytes).into_owned()))
}

/// Strip the framed-transport length prefix if one is present.
///
/// Thrift is used both framed and unframed. A framed message starts with a
/// four-byte length that matches what follows, so try the payload as-is first
/// and fall back to skipping the prefix — the version marker tells us which
/// interpretation was right.
fn strip_frame(payload: &[u8]) -> &[u8] {
    if parse_message(payload).is_some() {
        return payload;
    }
    payload.get(4..).unwrap_or(payload)
}

/// Whether a payload is a Thrift message. Used to recognise Thrift on the
/// assorted ports different services put it on.
pub(crate) fn looks_like_thrift(payload: &[u8]) -> bool {
    parse_message(strip_frame(payload)).is_some()
}

/// Dissect a Thrift message.
pub fn dissect_thrift(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match parse_message(strip_frame(payload)) {
        Some((kind, method)) => format!("Thrift {kind} — {}", super::truncate(&method, 48)),
        None => format!("Thrift ({})", super::bytes(payload.len() as u64)),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Thrift,
        summary,
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::VERSION_1;

    /// Build an unframed strict binary message.
    pub fn message(msg_type: u8, method: &str) -> Vec<u8> {
        let mut p = (VERSION_1 | msg_type as u32).to_be_bytes().to_vec();
        p.extend_from_slice(&(method.len() as u32).to_be_bytes());
        p.extend_from_slice(method.as_bytes());
        p.extend_from_slice(&1u32.to_be_bytes()); // sequence id
        p
    }

    /// Wrap a message in the framed transport's length prefix.
    pub fn framed(msg_type: u8, method: &str) -> Vec<u8> {
        let body = message(msg_type, method);
        let mut p = (body.len() as u32).to_be_bytes().to_vec();
        p.extend_from_slice(&body);
        p
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::{framed, message};
    use super::*;

    #[test]
    fn call_reports_the_method_name() {
        let r = dissect_thrift(None, None, 40000, 9090, &message(1, "getRegionInfo"));
        assert_eq!(r.protocol, Protocol::Thrift);
        assert_eq!(r.summary, "Thrift call — getRegionInfo");
    }

    #[test]
    fn replies_and_exceptions_are_distinguished() {
        let r = dissect_thrift(None, None, 9090, 40000, &message(2, "getRegionInfo"));
        assert_eq!(r.summary, "Thrift reply — getRegionInfo");
        let r = dissect_thrift(None, None, 9090, 40000, &message(3, "getRegionInfo"));
        assert_eq!(r.summary, "Thrift exception — getRegionInfo");
    }

    /// Thrift is used both framed and unframed, and the two look different at
    /// byte zero. Both have to decode to the same thing.
    #[test]
    fn framed_and_unframed_both_decode() {
        let unframed = dissect_thrift(None, None, 1, 9090, &message(1, "scannerOpen"));
        let with_frame = dissect_thrift(None, None, 1, 9090, &framed(1, "scannerOpen"));
        assert_eq!(unframed.summary, with_frame.summary);
        assert_eq!(with_frame.summary, "Thrift call — scannerOpen");
    }

    /// The version marker is what separates Thrift from arbitrary bytes.
    #[test]
    fn foreign_payloads_are_not_claimed() {
        assert!(!looks_like_thrift(b"GET / HTTP/1.1\r\n"));
        assert!(!looks_like_thrift(&[0u8; 32]));
        assert!(!looks_like_thrift(&[]));
        assert!(looks_like_thrift(&message(1, "ping")));
        assert!(looks_like_thrift(&framed(1, "ping")));
    }

    /// An implausible name length means we are misreading the stream, not
    /// looking at a method with a very long name.
    #[test]
    fn implausible_name_length_is_rejected() {
        let mut p = (VERSION_1 | 1u32).to_be_bytes().to_vec();
        p.extend_from_slice(&99_999u32.to_be_bytes());
        p.extend_from_slice(b"x");
        assert!(!looks_like_thrift(&p));

        let mut zero = (VERSION_1 | 1u32).to_be_bytes().to_vec();
        zero.extend_from_slice(&0u32.to_be_bytes());
        assert!(!looks_like_thrift(&zero));
    }

    /// A method name is an identifier; binary where the name should be means
    /// the version marker matched by coincidence.
    #[test]
    fn non_printable_method_name_is_rejected() {
        let mut p = (VERSION_1 | 1u32).to_be_bytes().to_vec();
        p.extend_from_slice(&4u32.to_be_bytes());
        p.extend_from_slice(&[0x00, 0x01, 0x02, 0x03]);
        assert!(!looks_like_thrift(&p));
    }

    #[test]
    fn unknown_message_type_is_not_claimed() {
        assert!(!looks_like_thrift(&message(9, "ping")));
    }

    #[test]
    fn long_method_names_are_truncated() {
        let long = "a".repeat(120);
        let r = dissect_thrift(None, None, 1, 9090, &message(1, &long));
        assert!(r.summary.contains('…'));
        assert!(r.summary.len() < 80);
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_thrift(None, None, 1, 9090, &[0x80, 0x01]);
        assert_eq!(r.summary, "Thrift (2 bytes)");
    }
}
