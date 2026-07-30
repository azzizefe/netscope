// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an AFP message (TCP 548) — Apple Filing Protocol for Mac file
/// sharing, framed by DSI. Byte 0 is the request/reply flag, byte 1 the DSI
/// command.
pub fn dissect_afp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match (payload.first(), payload.get(1)) {
        (Some(&flags), Some(&cmd)) => {
            let name = match cmd {
                1 => "CloseSession",
                2 => "Command",
                3 => "GetStatus",
                4 => "OpenSession",
                5 => "Tickle",
                6 => "Write",
                8 => "Attention",
                _ => "message",
            };
            let dir = if flags == 0 { "request" } else { "reply" };
            format!("AFP/DSI {name} {dir}")
        }
        _ => "AFP (truncated)".to_string(),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Afp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_session() {
        let r = dissect_afp(None, None, 40000, 548, &[0x00, 0x04, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Afp);
        assert_eq!(r.summary, "AFP/DSI OpenSession request");
    }
}
