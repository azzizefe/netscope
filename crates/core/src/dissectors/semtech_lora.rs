// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Semtech UDP Packet Forwarder (LoRaWAN Gateway, UDP 1680) frame.
pub fn dissect_semtech_lora(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        let version = payload[0];
        let token = u16::from_be_bytes([payload[1], payload[2]]);
        let id = payload[3];
        let cmd = match id {
            0x00 => "PUSH_DATA",
            0x01 => "PUSH_ACK",
            0x02 => "PULL_DATA",
            0x03 => "PULL_RESP",
            0x04 => "PULL_ACK",
            0x05 => "TX_ACK",
            _ => "Cmd",
        };
        format!("Semtech LoRa Packet Forwarder v{version} {cmd} (token 0x{token:04X})")
    } else {
        format!("Semtech LoRa Forwarder ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SemtechLora,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semtech_push_data() {
        let payload = vec![0x02, 0x12, 0x34, 0x00, 0x01, 0x02, 0x03, 0x04];
        let r = dissect_semtech_lora(None, None, 40000, 1680, &payload);
        assert_eq!(r.protocol, Protocol::SemtechLora);
        assert_eq!(r.summary, "Semtech LoRa Packet Forwarder v2 PUSH_DATA (token 0x1234)");
    }
}
