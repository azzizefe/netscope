// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{sigtran, DissectedResult};

/// Name the message within its class (RFC 3868 §3.1.2). SUA's own work splits
/// into a connectionless class and a connection-oriented one, mirroring the two
/// service modes SCCP offers.
fn message_name(class: u8, msg_type: u8) -> Option<&'static str> {
    Some(match (class, msg_type) {
        (0, 0) => "ERR",
        (0, 1) => "NTFY",
        (2, 1) => "DUNA",
        (2, 2) => "DAVA",
        (2, 3) => "DAUD",
        (2, 4) => "SCON",
        (2, 5) => "DUPU",
        (2, 6) => "DRST",
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
        // Connectionless: the mode almost all mobile signalling uses.
        (7, 1) => "CLDT",
        (7, 2) => "CLDR",
        // Connection-oriented.
        (8, 1) => "CORE",
        (8, 2) => "COAK",
        (8, 3) => "COREF",
        (8, 4) => "RELRE",
        (8, 5) => "RELCO",
        (8, 6) => "RESCO",
        (8, 7) => "RESRE",
        (8, 8) => "CODT",
        (8, 9) => "CODA",
        (8, 10) => "COERR",
        (8, 11) => "COIT",
        (9, 1) => "REG REQ",
        (9, 2) => "REG RSP",
        (9, 3) => "DEREG REQ",
        (9, 4) => "DEREG RSP",
        _ => return None,
    })
}

/// Dissect a SUA message — SS7 SCCP user adaptation over SCTP with payload
/// protocol identifier 4 (RFC 3868).
///
/// SUA takes the layer above M3UA: instead of carrying SCCP inside MTP3, it
/// replaces both, so an application can reach an SS7 network without an SS7
/// stack underneath it.
pub fn dissect_sua(
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
        protocol: Protocol::Sua,
        summary: sigtran::summarize("SUA", payload, message_name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissectors::sigtran::test_helpers::sigtran as build;

    #[test]
    fn connectionless_data_transfer() {
        let p = build(7, 1, 0x0113, b"tcap payload");
        let r = dissect_sua(None, None, 14001, 14001, &p);
        assert_eq!(r.protocol, Protocol::Sua);
        assert_eq!(r.summary, "SUA CLDT");
    }

    #[test]
    fn connection_oriented_request() {
        let p = build(8, 1, 0x0113, b"x");
        let r = dissect_sua(None, None, 14001, 14001, &p);
        assert_eq!(r.summary, "SUA CORE");
    }

    #[test]
    fn shared_housekeeping_messages_still_decode() {
        let p = build(3, 3, 0x0004, b"x");
        let r = dissect_sua(None, None, 14001, 14001, &p);
        assert_eq!(r.summary, "SUA BEAT");
    }

    #[test]
    fn unknown_type_falls_back_to_the_class() {
        let p = build(7, 42, 0x0113, b"x");
        let r = dissect_sua(None, None, 14001, 14001, &p);
        assert_eq!(r.summary, "SUA SUA-CL message 42");
    }
}
