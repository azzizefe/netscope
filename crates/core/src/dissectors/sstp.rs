// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// SSTP Control Packet Types (MS-SSTP §2.2.2).
fn sstp_control_type_name(packet_type: u16) -> &'static str {
    match packet_type {
        1 => "CALL_CONNECT_REQUEST",
        2 => "CALL_CONNECT_ACK",
        3 => "CALL_CONNECT_NAK",
        4 => "CALL_CONNECTED",
        5 => "CALL_DISCONNECT",
        6 => "CALL_DISCONNECT_ACK",
        7 => "ECHO_REQUEST",
        8 => "ECHO_RESPONSE",
        _ => "SSTP Control Packet",
    }
}

/// Dissect an SSTP (Secure Socket Tunneling Protocol over TCP 443 / HTTPS) frame.
pub fn dissect_sstp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        format!("SSTP ({})", super::bytes(payload.len() as u64))
    } else {
        let is_control = (payload[1] & 0x01) != 0;
        let length = u16::from_be_bytes([payload[2], payload[3]]);

        if is_control && payload.len() >= 6 {
            let ptype = u16::from_be_bytes([payload[4], payload[5]]);
            let name = sstp_control_type_name(ptype);
            format!("SSTP Control — {name} (len {length}B)")
        } else {
            format!("SSTP Data Frame — len {length}B")
        }
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Sstp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sstp_connect_request() {
        // Major = 1, Minor = 0 (Control = 1), Length = 14B, Packet Type = 1 (CALL_CONNECT_REQUEST)
        let payload = vec![0x10, 0x01, 0x00, 0x0E, 0x00, 0x01];
        let res = dissect_sstp(None, None, 443, 443, &payload);
        assert_eq!(res.protocol, Protocol::Sstp);
        assert!(res.summary.contains("CALL_CONNECT_REQUEST"));
    }

    #[test]
    fn test_sstp_short_payload() {
        let payload = vec![0x10, 0x01];
        let res = dissect_sstp(None, None, 443, 443, &payload);
        assert_eq!(res.protocol, Protocol::Sstp);
        assert!(res.summary.contains("SSTP (2 bytes)"));
    }
}
