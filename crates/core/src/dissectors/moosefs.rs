// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect MooseFS distributed file system messages (TCP 9419 master, 9420 chunkserver, 9421 mount).
pub fn dissect_moosefs(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let cmd = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let cmd_str = match cmd {
            100..=199 => "Chunkserver Command",
            200..=299 => "Client/Master Command",
            300..=399 => "Data Transfer",
            _ => "Command",
        };
        format!("MooseFS {cmd_str} (cmd {cmd})")
    } else {
        format!("MooseFS ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::MooseFs,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_moosefs_cmd() {
        let payload = vec![0x00, 0x00, 0x00, 0xC8, 0x00, 0x00, 0x00, 0x10]; // cmd 200
        let r = dissect_moosefs(None, None, 40000, 9421, &payload);
        assert_eq!(r.protocol, Protocol::MooseFs);
        assert!(r.summary.contains("MooseFS Client/Master Command"));
    }
}
