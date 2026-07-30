// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a PFCP message (UDP 8805) — the Packet Forwarding Control Protocol
/// that the 4G/5G control plane uses to program user-plane forwarding (the N4
/// interface). Byte 1 is the message type (3GPP TS 29.244).
pub fn dissect_pfcp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.get(1) {
        Some(&t) => {
            let name = match t {
                1 => "Heartbeat Request",
                2 => "Heartbeat Response",
                5 => "PFD Management Request",
                6 => "PFD Management Response",
                7 => "Association Setup Request",
                8 => "Association Setup Response",
                50 => "Session Establishment Request",
                51 => "Session Establishment Response",
                52 => "Session Modification Request",
                53 => "Session Modification Response",
                54 => "Session Deletion Request",
                55 => "Session Deletion Response",
                56 => "Session Report Request",
                57 => "Session Report Response",
                _ => "message",
            };
            format!("PFCP {name}")
        }
        None => "PFCP (truncated)".to_string(),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Pfcp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_establishment() {
        // version/flags, message type 50.
        let r = dissect_pfcp(None, None, 8805, 8805, &[0x21, 50, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Pfcp);
        assert_eq!(r.summary, "PFCP Session Establishment Request");
    }
}
