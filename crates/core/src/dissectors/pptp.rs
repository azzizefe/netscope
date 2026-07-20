// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The fixed PPTP magic cookie that follows the length and message type.
const MAGIC: [u8; 4] = [0x1A, 0x2B, 0x3C, 0x4D];

/// Dissect a PPTP control message (TCP 1723) — the control channel of the
/// legacy Microsoft VPN (its data rides GRE). Bytes 8..10 are the control
/// message type (RFC 2637).
pub fn dissect_pptp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 10 && payload[4..8] == MAGIC {
        let ctrl = u16::from_be_bytes([payload[8], payload[9]]);
        let name = match ctrl {
            1 => "Start-Control-Connection-Request",
            2 => "Start-Control-Connection-Reply",
            3 => "Stop-Control-Connection-Request",
            4 => "Stop-Control-Connection-Reply",
            5 => "Echo-Request",
            6 => "Echo-Reply",
            7 => "Outgoing-Call-Request",
            8 => "Outgoing-Call-Reply",
            15 => "Set-Link-Info",
            _ => "control message",
        };
        format!("PPTP {name}")
    } else {
        format!("PPTP ({})", super::bytes(payload.len() as u64))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Pptp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_control_connection() {
        let mut p = Vec::new();
        p.extend_from_slice(&156u16.to_be_bytes()); // length
        p.extend_from_slice(&1u16.to_be_bytes()); // message type: control
        p.extend_from_slice(&MAGIC);
        p.extend_from_slice(&1u16.to_be_bytes()); // SCCRQ
        let r = dissect_pptp(None, None, 40000, 1723, &p);
        assert_eq!(r.protocol, Protocol::Pptp);
        assert_eq!(r.summary, "PPTP Start-Control-Connection-Request");
    }
}
