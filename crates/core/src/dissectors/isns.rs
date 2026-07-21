// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! iSNS — how an iSCSI initiator finds its storage (RFC 4171, port 3205).
//!
//! An iSCSI initiator does not usually have its targets configured by hand. It
//! registers with an iSNS server, asks which targets it is allowed to see, and
//! subscribes to change notifications so it learns when one appears or goes
//! away. Fibre Channel over IP uses the same directory.
//!
//! That makes iSNS the place where "the storage disappeared" is actually
//! explained. When a target vanishes from an initiator, the cause is usually
//! not the target at all — it is a query that came back empty, a registration
//! that expired, or an authorisation that was refused. Each of those is a
//! different status code in the response, and at the initiator they produce the
//! same symptom: a LUN that is simply no longer there.
//!
//! Every response carries a four-byte status code, and every response function
//! ID is its request's with the top bit set. Both of those make the direction
//! and the outcome readable without tracking state across packets.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Version, function ID, PDU length, flags, transaction ID, sequence ID.
const HEADER_LEN: usize = 12;

/// The bit that turns a request's function ID into its response's.
const RESPONSE_BIT: u16 = 0x8000;

/// What the message is asking for, with the response bit already cleared.
fn function_name(function: u16) -> Option<&'static str> {
    Some(match function {
        0x0001 => "device attribute registration",
        0x0002 => "device attribute query",
        0x0003 => "device get next",
        0x0004 => "device deregistration",
        0x0005 => "state change notification registration",
        0x0006 => "state change notification deregistration",
        0x0007 => "state change event",
        0x0008 => "state change notification",
        0x0009 => "discovery domain registration",
        0x000a => "discovery domain deregistration",
        0x000b => "discovery domain set registration",
        0x000c => "discovery domain set deregistration",
        0x000d => "entity status inquiry",
        0x000e => "heartbeat",
        0x0011 => "request FC domain ID",
        0x0012 => "release FC domain ID",
        0x0013 => "get FC domain ID",
        _ => return None,
    })
}

/// Why the server refused, or that it did not.
fn status_name(status: u32) -> Option<&'static str> {
    Some(match status {
        0 => "no error",
        1 => "unknown error",
        2 => "message format error",
        3 => "invalid registration",
        5 => "invalid query",
        6 => "source unknown",
        7 => "source absent",
        8 => "source unauthorised",
        9 => "no such entry",
        10 => "version not supported",
        11 => "internal error",
        12 => "busy",
        13 => "option not understood",
        14 => "invalid update",
        15 => "function not supported",
        16 => "state change notification event rejected",
        17 => "state change notification registration rejected",
        18 => "attribute not implemented",
        19 => "FC domain ID not available",
        20 => "FC domain ID not allocated",
        21 => "entity status inquiry not available",
        22 => "invalid deregistration",
        23 => "registration feature not supported",
        _ => return None,
    })
}

/// Dissect an iSNS message.
pub fn dissect_isns(
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
        protocol: Protocol::Isns,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    let Some(head) = payload.get(..HEADER_LEN) else {
        return "iSNS".to_string();
    };
    let raw_function = u16::from_be_bytes([head[2], head[3]]);
    let is_response = raw_function & RESPONSE_BIT != 0;
    // The response ID is the request's with one bit set, so clearing it is what
    // makes both directions read from a single table.
    let function = raw_function & !RESPONSE_BIT;

    let Some(name) = function_name(function) else {
        return format!("iSNS (function {function:#06x})");
    };

    if !is_response {
        return format!("iSNS {name}");
    }

    // A response opens with its status, which is the whole point of reading it.
    let Some(status) = payload
        .get(HEADER_LEN..HEADER_LEN + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    else {
        return format!("iSNS {name} response");
    };
    // A status the standard has not assigned keeps its number rather than being
    // mapped to the nearest entry that happens to exist.
    let reason = match status_name(status) {
        Some(text) => text.to_string(),
        None => format!("status {status}"),
    };
    if status == 0 {
        format!("iSNS {name} response — ok")
    } else {
        format!("iSNS {name} failed — {reason}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an iSNS message. A status is only appended for responses.
    fn message(function: u16, status: Option<u32>) -> Vec<u8> {
        let mut p = 0x0001u16.to_be_bytes().to_vec();
        p.extend_from_slice(&function.to_be_bytes());
        p.extend_from_slice(&0u16.to_be_bytes());
        p.extend_from_slice(&0u16.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&0u16.to_be_bytes());
        if let Some(status) = status {
            p.extend_from_slice(&status.to_be_bytes());
        }
        p
    }

    /// The reason this dissector exists: a target that "disappeared" is
    /// usually a query the server refused, and it says why.
    #[test]
    fn a_refused_query_says_why() {
        let r = dissect_isns(None, None, 3205, 40000, &message(0x8002, Some(8)));
        assert_eq!(r.protocol, Protocol::Isns);
        assert_eq!(
            r.summary,
            "iSNS device attribute query failed — source unauthorised"
        );
    }

    /// The failures that produce an identical symptom at the initiator have to
    /// be told apart here, because nowhere else distinguishes them.
    #[test]
    fn the_failure_reasons_are_distinguished() {
        assert!(describe(&message(0x8002, Some(9))).contains("no such entry"));
        assert!(describe(&message(0x8001, Some(3))).contains("invalid registration"));
        assert!(describe(&message(0x8001, Some(22))).contains("invalid deregistration"));
        assert!(describe(&message(0x8005, Some(17))).contains("registration rejected"));
    }

    /// Status zero is a success and must not read as a failure.
    #[test]
    fn a_successful_response_is_not_reported_as_a_failure() {
        let ok = describe(&message(0x8001, Some(0)));
        assert_eq!(ok, "iSNS device attribute registration response — ok");
        assert!(!ok.contains("failed"), "{ok}");
    }

    /// Direction is one bit, and clearing it is what lets both directions read
    /// from a single table. Without that a response would be an unknown
    /// function rather than a named one.
    #[test]
    fn the_response_bit_is_cleared_before_the_lookup() {
        assert_eq!(
            describe(&message(0x0002, None)),
            "iSNS device attribute query"
        );
        assert!(describe(&message(0x8002, Some(0))).contains("device attribute query"));
    }

    /// A status outside the standard keeps its number.
    #[test]
    fn an_unassigned_status_keeps_its_number() {
        assert!(describe(&message(0x8001, Some(99))).contains("status 99"));
        // 4 is explicitly reserved, so it has no name either.
        assert!(describe(&message(0x8001, Some(4))).contains("status 4"));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "iSNS");
        assert_eq!(describe(&[0u8; 11]), "iSNS");
        // A response whose status word has not arrived.
        assert_eq!(
            describe(&message(0x8001, None)),
            "iSNS device attribute registration response"
        );
        assert_eq!(describe(&message(0x00FF, None)), "iSNS (function 0x00ff)");
    }
}
