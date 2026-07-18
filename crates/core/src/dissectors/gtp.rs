// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a GTP message (UDP 2123 control / 2152 user) — GPRS Tunnelling
/// Protocol, the core of mobile (3G/4G/5G) data networks. Byte 1 is the
/// message type (3GPP TS 29.060 / 29.281).
pub fn dissect_gtp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
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
