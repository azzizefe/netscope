// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an SMPP PDU (TCP 2775) — the protocol SMS gateways speak to send
/// and receive text messages. Bytes 4..8 are the command id (SMPP v3.4).
pub fn dissect_smpp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let command_id = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let name = match command_id {
            0x0000_0001 => "bind_receiver",
            0x0000_0002 => "bind_transmitter",
            0x0000_0004 => "submit_sm",
            0x0000_0005 => "deliver_sm",
            0x0000_0009 => "bind_transceiver",
            0x0000_0015 => "enquire_link",
            0x8000_0004 => "submit_sm_resp",
            0x8000_0009 => "bind_transceiver_resp",
            _ => "PDU",
        };
        format!("SMPP {name}")
    } else {
        format!("SMPP ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Smpp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submit_sm() {
        // length (4) + command_id 0x00000004 (submit_sm).
        let r = dissect_smpp(
            None,
            None,
            40000,
            2775,
            &[0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x04],
        );
        assert_eq!(r.protocol, Protocol::Smpp);
        assert_eq!(r.summary, "SMPP submit_sm");
    }
}
