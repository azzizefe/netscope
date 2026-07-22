// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect Coda RPC2 distributed file system messages (UDP 2430-2433).
pub fn dissect_coda(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        let pkt_type = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let name = match pkt_type {
            0 => "INIT1",
            1 => "INIT2",
            2 => "INIT3",
            3 => "INIT4",
            4 => "INITMULTICAST",
            5 => "DISC",
            6 => "DATA",
            7 => "ACK",
            8 => "BUSY",
            _ => "RPC2 Packet",
        };
        format!("Coda RPC2 {name}")
    } else {
        format!("Coda ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Coda,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coda_data() {
        let payload = vec![0x00, 0x00, 0x00, 0x06]; // RPC2_DATA
        let r = dissect_coda(None, None, 40000, 2430, &payload);
        assert_eq!(r.protocol, Protocol::Coda);
        assert_eq!(r.summary, "Coda RPC2 DATA");
    }
}
