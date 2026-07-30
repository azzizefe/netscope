// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Mumble control message (TCP 64738) — a low-latency voice-chat
/// protocol. Each message is a 2-byte type + 4-byte length, then a protobuf
/// body (the voice audio itself rides a separate UDP path).
pub fn dissect_mumble(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 2 {
        let msg_type = u16::from_be_bytes([payload[0], payload[1]]);
        let name = match msg_type {
            0 => "Version",
            1 => "UDPTunnel",
            2 => "Authenticate",
            3 => "Ping",
            5 => "Reject",
            6 => "ServerSync",
            7 => "ChannelRemove",
            9 => "UserRemove",
            10 => "UserState",
            11 => "TextMessage",
            _ => "message",
        };
        format!("Mumble {name}")
    } else {
        "Mumble (truncated)".to_string()
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Mumble,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticate() {
        let r = dissect_mumble(None, None, 40000, 64738, &[0x00, 0x02, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Mumble);
        assert_eq!(r.summary, "Mumble Authenticate");
    }
}
