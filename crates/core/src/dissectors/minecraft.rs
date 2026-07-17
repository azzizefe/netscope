// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Minecraft (Java Edition) message (TCP 25565). Packets are
/// length-prefixed varints; the modern handshake is packet id 0x00 right after
/// the length, and the legacy server-list ping starts with 0xFE.
pub fn dissect_minecraft(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.first() {
        Some(0xFE) => "Minecraft legacy server ping".to_string(),
        // A short single-byte length varint (high bit clear) followed by packet
        // id 0x00 is the handshake / status request.
        Some(&len) if len < 0x80 && payload.get(1) == Some(&0x00) => {
            "Minecraft handshake".to_string()
        }
        _ => format!("Minecraft packet ({} bytes)", payload.len()),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Minecraft,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake() {
        // length varint 0x10, packet id 0x00, protocol version varint…
        let r = dissect_minecraft(None, None, 40000, 25565, &[0x10, 0x00, 0xF7, 0x05]);
        assert_eq!(r.protocol, Protocol::Minecraft);
        assert_eq!(r.summary, "Minecraft handshake");
    }
}
