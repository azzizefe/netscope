// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an STT (Stateless Transport Tunneling — TCP 8472 / 7471) packet.
pub fn dissect_stt(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 18 {
        format!("STT Tunnel ({})", super::bytes(payload.len() as u64))
    } else {
        let version = payload[0];
        let flags = payload[1];
        let l4_proto = payload[2];
        let context_id = u64::from_be_bytes([
            payload[8], payload[9], payload[10], payload[11],
            payload[12], payload[13], payload[14], payload[15],
        ]);

        format!("STT Tunnel v{version} — Context ID 0x{context_id:016X} (L4 Proto {l4_proto}, Flags 0x{flags:02X})")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Stt,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stt_tunnel() {
        let mut payload = vec![0u8; 18];
        payload[0] = 0; // Version 0
        payload[2] = 6; // L4 Proto TCP
        payload[15] = 0x42; // Context ID

        let res = dissect_stt(None, None, 8472, 8472, &payload);
        assert_eq!(res.protocol, Protocol::Stt);
        assert!(res.summary.contains("Context ID 0x0000000000000042"));
    }

    #[test]
    fn test_stt_short_payload() {
        let payload = vec![0x00, 0x01];
        let res = dissect_stt(None, None, 8472, 8472, &payload);
        assert_eq!(res.protocol, Protocol::Stt);
        assert!(res.summary.contains("STT Tunnel (2 bytes)"));
    }
}
