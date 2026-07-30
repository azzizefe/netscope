// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{gtpv2, DissectedResult};

/// The user-data message type: everything a phone actually sends and receives
/// travels inside one of these.
const MSG_G_PDU: u8 = 255;
/// The mandatory part of the header, before any optional fields.
const BASE_HEADER: usize = 8;
/// Flags saying an optional block follows the mandatory header.
const FLAG_EXTENSION: u8 = 0x04;
const FLAG_SEQUENCE: u8 = 0x02;
const FLAG_N_PDU: u8 = 0x01;

/// Work out where the payload starts.
///
/// The optional sequence number, N-PDU number and extension-header flag are
/// signalled individually but the four bytes holding them are present if *any*
/// of the three is set, and a chain of extension headers may follow. Assuming a
/// fixed eight-byte header lands in the middle of that block.
fn payload_offset(payload: &[u8]) -> Option<usize> {
    let flags = *payload.first()?;
    if flags & (FLAG_EXTENSION | FLAG_SEQUENCE | FLAG_N_PDU) == 0 {
        return Some(BASE_HEADER);
    }
    let mut offset = BASE_HEADER + 4;
    // The last byte of that block names the first extension header, if any.
    let mut next = *payload.get(BASE_HEADER + 3)?;
    // A real chain is short; the cap keeps a malformed one from spinning.
    for _ in 0..8 {
        if next == 0 {
            return Some(offset);
        }
        // Each extension header declares its own length in 4-byte units and
        // ends with the type of the one after it.
        let length = *payload.get(offset)? as usize * 4;
        if length == 0 {
            return None;
        }
        next = *payload.get(offset + length - 1)?;
        offset += length;
    }
    None
}

/// Dissect a GTP message (UDP 2123 control / 2152 user) — GPRS Tunnelling
/// Protocol, the core of mobile (3G/4G/5G) data networks. Byte 1 is the
/// message type (3GPP TS 29.060 / 29.281).
///
/// Both GTP versions share these ports but are different protocols with
/// different message-type tables, so the version in the top three bits of the
/// first byte decides which one to hand off to. Without this check a v2 message
/// would be read against the v1 table and mislabelled.
pub fn dissect_gtp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    if payload.first().map(|b| b >> 5) == Some(2) {
        return gtpv2::dissect_gtpv2(src_ip, dst_ip, src_port, dst_port, payload);
    }

    // A G-PDU is a phone's actual traffic wrapped in a tunnel. Reporting it as
    // "GTP G-PDU" hides everything a mobile capture is taken to look at, so
    // unwrap it and report what is inside.
    if payload.get(1) == Some(&MSG_G_PDU) {
        if let Some(offset) = payload_offset(payload) {
            if let Some(inner) = payload.get(offset..) {
                let ethertype = match inner.first().map(|b| b >> 4) {
                    Some(4) => Some(0x0800u16),
                    Some(6) => Some(0x86DDu16),
                    _ => None,
                };
                if let Some(et) = ethertype {
                    let mut r = super::dispatch_l3(et, inner, 0);
                    r.summary = format!("GTP-U · {}", r.summary);
                    return r;
                }
            }
        }
    }

    let summary = match payload.get(1) {
        Some(&t) => {
            let name = match t {
                1 => "Echo Request",
                2 => "Echo Response",
                16 => "Create PDP Context Request",
                17 => "Create PDP Context Response",
                18 => "Update PDP Context Request",
                20 => "Delete PDP Context Request",
                21 => "Delete PDP Context Response",
                32 => "Create Session Request",
                33 => "Create Session Response",
                255 => "G-PDU (user data)",
                _ => "message",
            };
            format!("GTP {name}")
        }
        None => "GTP (empty)".to_string(),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Gtp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GTPv2-C shares these ports; it must reach its own dissector rather than
    /// being read against the v1 message table.
    #[test]
    fn version_two_is_handed_to_the_gtpv2_dissector() {
        let mut p = vec![0x48, 34, 0x00, 0x00]; // v2, T flag, Modify Bearer Request
        p.extend_from_slice(&1u32.to_be_bytes());
        p.extend_from_slice(&[0, 0, 5, 0]);
        let r = dissect_gtp(None, None, 2123, 2123, &p);
        assert_eq!(r.protocol, Protocol::Gtpv2);
        assert_eq!(
            r.summary,
            "GTPv2-C Modify Bearer Request — TEID 0x00000001, seq 5"
        );
    }

    #[test]
    fn version_one_still_uses_the_v1_table() {
        let r = dissect_gtp(None, None, 2123, 2123, &[0x32, 16, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Gtp);
        assert_eq!(r.summary, "GTP Create PDP Context Request");
    }

    #[test]
    fn user_data() {
        let r = dissect_gtp(None, None, 2152, 2152, &[0x30, 0xFF, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Gtp);
        assert_eq!(r.summary, "GTP G-PDU (user data)");
    }

    #[test]
    fn echo_request() {
        let r = dissect_gtp(None, None, 2123, 2123, &[0x32, 0x01, 0x00, 0x00]);
        assert_eq!(r.summary, "GTP Echo Request");
    }
}
