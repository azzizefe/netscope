// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{sigtran, DissectedResult};

/// Name the message within its class (RFC 3331 §3.1.2). M2UA's own work happens
/// in the MAUP class; the other classes are the SIGTRAN housekeeping shared
/// with M3UA.
fn message_name(class: u8, msg_type: u8) -> Option<&'static str> {
    Some(match (class, msg_type) {
        (0, 0) => "ERR",
        (0, 1) => "NTFY",
        (3, 1) => "ASPUP",
        (3, 2) => "ASPDN",
        (3, 3) => "BEAT",
        (3, 4) => "ASPUP ACK",
        (3, 5) => "ASPDN ACK",
        (3, 6) => "BEAT ACK",
        (4, 1) => "ASPAC",
        (4, 2) => "ASPIA",
        (4, 3) => "ASPAC ACK",
        (4, 4) => "ASPIA ACK",
        (6, 1) => "Data",
        (6, 2) => "Establish Request",
        (6, 3) => "Establish Confirm",
        (6, 4) => "Release Request",
        (6, 5) => "Release Confirm",
        (6, 6) => "Release Indication",
        (6, 7) => "State Request",
        (6, 8) => "State Confirm",
        (6, 9) => "State Indication",
        (6, 10) => "Data Retrieval Request",
        (6, 11) => "Data Retrieval Confirm",
        (6, 12) => "Data Retrieval Indication",
        (6, 13) => "Data Retrieval Complete Indication",
        (6, 14) => "Congestion Indication",
        (6, 15) => "Data Acknowledge",
        (10, 1) => "REG REQ",
        (10, 2) => "REG RSP",
        (10, 3) => "DEREG REQ",
        (10, 4) => "DEREG RSP",
        _ => return None,
    })
}

/// Dissect an M2UA message — SS7 MTP2 link state carried over SCTP with payload
/// protocol identifier 2 (RFC 3331).
///
/// Where M3UA replaces the SS7 routing layer, M2UA replaces the layer below it:
/// it lets a signalling gateway present a remote SS7 link to a media gateway
/// controller as though it were locally attached.
pub fn dissect_m2ua(
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
        protocol: Protocol::M2ua,
        summary: sigtran::summarize("M2UA", payload, message_name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissectors::sigtran::test_helpers::sigtran as build;

    #[test]
    fn maup_data_is_named() {
        let p = build(6, 1, 0x0300, b"link data");
        let r = dissect_m2ua(None, None, 2904, 2904, &p);
        assert_eq!(r.protocol, Protocol::M2ua);
        assert_eq!(r.summary, "M2UA Data");
    }

    #[test]
    fn state_indication_is_named() {
        let p = build(6, 9, 0x0300, b"x");
        let r = dissect_m2ua(None, None, 2904, 2904, &p);
        assert_eq!(r.summary, "M2UA State Indication");
    }

    #[test]
    fn unknown_type_falls_back_to_the_class() {
        let p = build(6, 99, 0x0300, b"x");
        let r = dissect_m2ua(None, None, 2904, 2904, &p);
        assert_eq!(r.summary, "M2UA MAUP message 99");
    }

    #[test]
    fn garbage_does_not_panic() {
        let r = dissect_m2ua(None, None, 2904, 2904, &[0xff; 2]);
        assert_eq!(r.summary, "M2UA (2 bytes)");
    }
}
