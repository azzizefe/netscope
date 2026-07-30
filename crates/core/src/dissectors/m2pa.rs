// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{sigtran, DissectedResult};

/// Name the message (RFC 4165 §2.1). M2PA has just one class of its own with
/// two messages in it — the protocol is deliberately thin.
fn message_name(class: u8, msg_type: u8) -> Option<&'static str> {
    Some(match (class, msg_type) {
        (11, 1) => "User Data",
        (11, 2) => "Link Status",
        _ => return None,
    })
}

/// Dissect an M2PA message — an SS7 MTP2 peer link carried over SCTP with
/// payload protocol identifier 5 (RFC 4165).
///
/// M2PA and M2UA both replace SS7's link layer, but differently: M2UA presents
/// a remote link to a controller, while M2PA replaces the link itself, so two
/// signalling points talk MTP3 to each other directly over IP.
pub fn dissect_m2pa(
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
        protocol: Protocol::M2pa,
        summary: sigtran::summarize("M2PA", payload, message_name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissectors::sigtran::test_helpers::sigtran as build;

    #[test]
    fn user_data() {
        let p = build(11, 1, 0x0300, b"mtp3 payload");
        let r = dissect_m2pa(None, None, 3565, 3565, &p);
        assert_eq!(r.protocol, Protocol::M2pa);
        assert_eq!(r.summary, "M2PA User Data");
    }

    #[test]
    fn link_status() {
        let p = build(11, 2, 0x0300, b"x");
        let r = dissect_m2pa(None, None, 3565, 3565, &p);
        assert_eq!(r.summary, "M2PA Link Status");
    }

    /// Class 11 is M2PA's own and is not in the shared class table, so an
    /// unknown type has nothing to fall back on but the raw numbers.
    #[test]
    fn unknown_type_reports_the_numbers() {
        let p = build(11, 7, 0x0300, b"x");
        let r = dissect_m2pa(None, None, 3565, 3565, &p);
        assert_eq!(r.summary, "M2PA class 11 message 7");
    }
}
