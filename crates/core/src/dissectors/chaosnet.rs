// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Chaosnet protocol frame (EtherType 0x0804).
pub fn dissect_chaosnet(payload: &[u8]) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        let opcode = payload[0];
        let name = match opcode {
            0x01 => "RFC (Request for Connection)",
            0x02 => "OPN (Open Connection)",
            0x03 => "CLS (Close Connection)",
            0x04 => "FWD (Forward Connection)",
            0x05 => "ANS (Answer)",
            0x06 => "SNS (Sense Status)",
            0x07 => "STS (Status)",
            0x08 => "RUT (Routing Info)",
            0x09 => "LOS (Loss Connection)",
            0x0A => "EOF (End of File)",
            0x0B => "UNC (Uncontrolled Data)",
            0x80 => "DAT (Data)",
            _ => "Packet",
        };
        format!("Chaosnet {name}")
    } else {
        format!("Chaosnet ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Chaosnet,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chaosnet_rfc() {
        let payload = vec![0x01, 0x00, 0x00, 0x08];
        let r = dissect_chaosnet(&payload);
        assert_eq!(r.protocol, Protocol::Chaosnet);
        assert_eq!(r.summary, "Chaosnet RFC (Request for Connection)");
    }
}
