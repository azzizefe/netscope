// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an NDMP message (TCP 10000) — the Network Data Management Protocol
/// backup software uses to drive NAS backups. The header carries a sequence,
/// timestamp, message type (request/reply) and the operation code.
pub fn dissect_ndmp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 16 {
        let msg_type = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let op = u32::from_be_bytes([payload[12], payload[13], payload[14], payload[15]]);
        let name = match op {
            0x900 => "CONNECT_OPEN",
            0x901 => "CONNECT_CLIENT_AUTH",
            0x100 => "CONFIG_GET_HOST_INFO",
            0x400 => "SCSI_OPEN",
            0x500 => "TAPE_OPEN",
            0x502 => "DATA_START_BACKUP",
            0x503 => "DATA_START_RECOVER",
            _ => "operation",
        };
        let dir = if msg_type == 0 { "request" } else { "reply" };
        format!("NDMP {name} {dir}")
    } else {
        format!("NDMP ({})", super::bytes(payload.len() as u64))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ndmp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_open_request() {
        let mut p = Vec::new();
        p.extend_from_slice(&1u32.to_be_bytes()); // sequence
        p.extend_from_slice(&0u32.to_be_bytes()); // timestamp
        p.extend_from_slice(&0u32.to_be_bytes()); // msg type: request
        p.extend_from_slice(&0x900u32.to_be_bytes()); // CONNECT_OPEN
        let r = dissect_ndmp(None, None, 40000, 10000, &p);
        assert_eq!(r.protocol, Protocol::Ndmp);
        assert_eq!(r.summary, "NDMP CONNECT_OPEN request");
    }
}
