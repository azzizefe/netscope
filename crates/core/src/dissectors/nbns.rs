// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a NetBIOS Name Service message (UDP 137). NBNS reuses the DNS
/// header layout: after the id, byte 2 bit 0x80 is the response flag and the
/// opcode sits in the next four bits (RFC 1002).
pub fn dissect_nbns(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        let kind = if flags & 0x8000 != 0 {
            "Response"
        } else {
            "Query"
        };
        let op = match (flags >> 11) & 0x0F {
            0 => "Name",
            5 => "Registration",
            6 => "Release",
            7 => "WACK",
            8 => "Refresh",
            _ => "",
        };
        if op.is_empty() {
            format!("NBNS {kind}")
        } else {
            format!("NBNS {op} {kind}")
        }
    } else {
        "NBNS (truncated)".to_string()
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Nbns,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_query() {
        // id=0x1234, flags=0x0110 (query, recursion desired) -> opcode 0.
        let r = dissect_nbns(None, None, 137, 137, &[0x12, 0x34, 0x01, 0x10]);
        assert_eq!(r.protocol, Protocol::Nbns);
        assert_eq!(r.summary, "NBNS Name Query");
    }

    #[test]
    fn registration_response() {
        // flags 0x8000 (response) | (5 << 11) registration = 0xA800.
        let r = dissect_nbns(None, None, 137, 137, &[0x00, 0x01, 0xA8, 0x00]);
        assert_eq!(r.summary, "NBNS Registration Response");
    }
}
