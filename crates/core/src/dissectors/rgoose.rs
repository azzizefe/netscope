// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! R-GOOSE and R-SV — substation trip messages, made routable.
//!
//! A GOOSE message is a protection relay telling a circuit breaker to open. It
//! has to arrive in under four milliseconds, which is why ordinary
//! [`super::goose`] rides directly on Ethernet with no IP layer to slow it down.
//! IEC 61850-90-5 adds a session header so the same messages can be **routed** —
//! between substations, across a wide-area link, into a control centre.
//!
//! Routing a trip command is exactly as consequential as it sounds, and the
//! session header exists mostly to make it survivable. Two of its fields decide
//! whether it is.
//!
//! ## The simulation flag
//!
//! Every APDU carries a simulation bit. Set, the message is test traffic; clear,
//! it is real. A relay only honours simulated messages when it has itself been
//! put into test mode, so the two must agree — and when they do not, the failure
//! is silent in the worst direction. A relay left in test mode ignores a real
//! trip. A relay out of test mode acts on a commissioning engineer's simulation.
//! Neither logs anything that says so.
//!
//! ## Authentication
//!
//! The header carries a key identifier and an initialisation vector because a
//! routable trip message that nobody authenticates is a trip anyone who can
//! reach the network can forge. A key identifier of zero with no vector is
//! precisely that: unauthenticated, routable, and able to open a breaker.
//!
//! The SPDU number is a sequence. Gaps in it are trip messages that did not
//! arrive, on a path where four milliseconds is the budget.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Identifier, header length, content indicator, length, SPDU length, SPDU
/// number, version, key times, key identifier, vector length.
const SESSION_HEADER: usize = 25;

/// The smallest R-GOOSE Wireshark will consider.
const MINIMUM: usize = 27;

const SPDU_TUNNELED: u8 = 0xA0;
const SPDU_GOOSE: u8 = 0xA1;
const SPDU_SV: u8 = 0xA2;
const SPDU_MANAGEMENT: u8 = 0xA3;

fn spdu_name(id: u8) -> Option<&'static str> {
    Some(match id {
        SPDU_TUNNELED => "tunnelled",
        SPDU_GOOSE => "R-GOOSE",
        SPDU_SV => "R-SV",
        SPDU_MANAGEMENT => "management",
        _ => return None,
    })
}

/// Whether a payload opens with a session identifier this understands.
pub(crate) fn looks_like_rgoose(payload: &[u8]) -> bool {
    payload.len() >= MINIMUM && payload.first().is_some_and(|id| spdu_name(*id).is_some())
}

/// Dissect an R-GOOSE or R-SV session (UDP 102, over CLTP).
pub fn dissect_rgoose(
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
        protocol: Protocol::Rgoose,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    let Some(head) = payload.get(..SESSION_HEADER) else {
        return format!("R-GOOSE ({})", super::bytes(payload.len() as u64));
    };
    let Some(name) = spdu_name(head[0]) else {
        return format!("R-GOOSE (session {:#04x})", head[0]);
    };

    let spdu_number = u32::from_be_bytes([head[8], head[9], head[10], head[11]]);
    let key_id = u32::from_be_bytes([head[20], head[21], head[22], head[23]]);
    // The vector length is what separates a signed session from a bare one, and
    // it also decides where the payload begins.
    let vector = head[24] as usize;

    // A routable trip nobody authenticates is a trip anyone on the path can
    // forge. This is worth saying before anything else about the message.
    let authentication = if key_id == 0 && vector == 0 {
        " — NOT AUTHENTICATED"
    } else {
        ""
    };

    // The payload follows the vector: four bytes of length, then each APDU as
    // a tag, a simulation flag, an application identifier and a length.
    let payload_start = SESSION_HEADER + vector;
    let Some(apdu) = payload.get(payload_start + 4..payload_start + 8) else {
        return format!("{name} SPDU {spdu_number}{authentication}");
    };

    let simulated = apdu[1] != 0;
    let appid = u16::from_be_bytes([apdu[2], apdu[3]]);

    // Test traffic and real traffic are indistinguishable except for this bit,
    // and a relay whose test mode disagrees with it fails silently.
    let simulation = if simulated { " [SIMULATED]" } else { "" };

    format!("{name} APPID {appid:#06x}, SPDU {spdu_number}{simulation}{authentication}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an R-GOOSE session.
    fn session(
        id: u8,
        spdu: u32,
        key_id: u32,
        vector: usize,
        simulated: bool,
        appid: u16,
    ) -> Vec<u8> {
        let mut v = vec![id, 0x18, 0x80, 0x16];
        v.extend_from_slice(&64u32.to_be_bytes()); // SPDU length
        v.extend_from_slice(&spdu.to_be_bytes()); // SPDU number
        v.extend_from_slice(&1u16.to_be_bytes()); // version
        v.extend_from_slice(&0u32.to_be_bytes()); // time of current key
        v.extend_from_slice(&0u16.to_be_bytes()); // time of next key
        v.extend_from_slice(&key_id.to_be_bytes()); // key identifier
        v.push(vector as u8);
        v.extend_from_slice(&vec![0xAA; vector]); // initialisation vector
        v.extend_from_slice(&16u32.to_be_bytes()); // payload length
        v.push(0x81); // APDU tag — GOOSE
        v.push(if simulated { 0x01 } else { 0x00 });
        v.extend_from_slice(&appid.to_be_bytes());
        v.extend_from_slice(&8u16.to_be_bytes()); // APDU length
        v.extend_from_slice(&[0u8; 8]);
        v
    }

    /// The reason this dissector exists: a routable trip command that nobody
    /// authenticated can be forged by anyone who can reach the network.
    #[test]
    fn an_unauthenticated_session_is_called_out() {
        let r = dissect_rgoose(
            None,
            None,
            40000,
            102,
            &session(SPDU_GOOSE, 7, 0, 0, false, 0x0001),
        );
        assert_eq!(r.protocol, Protocol::Rgoose);
        assert_eq!(
            r.summary,
            "R-GOOSE APPID 0x0001, SPDU 7 — NOT AUTHENTICATED"
        );
    }

    /// A session with a key and a vector is not called out.
    #[test]
    fn an_authenticated_session_is_not_flagged() {
        let summary = describe(&session(SPDU_GOOSE, 7, 42, 16, false, 0x0001));
        assert!(!summary.contains("NOT AUTHENTICATED"), "{summary}");
        assert!(summary.contains("APPID 0x0001"), "{summary}");
    }

    /// Test traffic and real traffic differ by one bit, and a relay whose test
    /// mode disagrees with it either ignores a real trip or acts on a fake one.
    #[test]
    fn simulated_traffic_is_distinguished_from_real() {
        let test = describe(&session(SPDU_GOOSE, 1, 42, 16, true, 0x0001));
        let real = describe(&session(SPDU_GOOSE, 1, 42, 16, false, 0x0001));
        assert!(test.contains("[SIMULATED]"), "{test}");
        assert!(!real.contains("SIMULATED"), "{real}");
    }

    /// The vector length decides where the payload begins. Ignoring it reads
    /// the simulation flag out of the vector's random bytes, which makes the
    /// test/real distinction meaningless.
    #[test]
    fn the_vector_length_moves_the_payload() {
        let with = describe(&session(SPDU_GOOSE, 1, 42, 16, true, 0x1234));
        let without = describe(&session(SPDU_GOOSE, 1, 42, 0, true, 0x1234));
        assert!(with.contains("APPID 0x1234"), "{with}");
        assert!(without.contains("APPID 0x1234"), "{without}");
        assert!(with.contains("SIMULATED") && without.contains("SIMULATED"));
    }

    /// Sample values and trip messages share the session format.
    #[test]
    fn the_session_types_are_named() {
        assert!(describe(&session(SPDU_SV, 1, 1, 0, false, 1)).starts_with("R-SV"));
        assert!(describe(&session(SPDU_MANAGEMENT, 1, 1, 0, false, 1)).starts_with("management"));
        assert!(describe(&session(SPDU_TUNNELED, 1, 1, 0, false, 1)).starts_with("tunnelled"));
    }

    /// Gaps in the sequence are trip messages that never arrived.
    #[test]
    fn the_spdu_number_is_reported() {
        assert!(describe(&session(SPDU_GOOSE, 1, 1, 0, false, 1)).contains("SPDU 1"));
        assert!(describe(&session(SPDU_GOOSE, 99, 1, 0, false, 1)).contains("SPDU 99"));
    }

    /// The guard must not claim arbitrary traffic on a shared port.
    #[test]
    fn the_guard_needs_a_known_session_identifier() {
        assert!(looks_like_rgoose(&session(SPDU_GOOSE, 1, 1, 0, false, 1)));
        assert!(!looks_like_rgoose(&[0x03; 40]), "not a session identifier");
        assert!(!looks_like_rgoose(&[SPDU_GOOSE; 10]), "too short");
        assert!(!looks_like_rgoose(
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        ));
        assert!(!looks_like_rgoose(&[]));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "R-GOOSE (0 bytes)");
        assert_eq!(describe(&[0xA1; 24]), "R-GOOSE (24 bytes)");
        assert!(describe(&[0x55; 30]).contains("session 0x55"));
        // A session header with no payload after it still reports the sequence.
        let mut short = session(SPDU_GOOSE, 3, 1, 0, false, 1);
        short.truncate(SESSION_HEADER + 2);
        assert_eq!(describe(&short), "R-GOOSE SPDU 3");
    }
}
