// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect BeeGFS storage/metadata node messages (TCP/UDP 8003).
pub fn dissect_beegfs(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"BGFS") {
        "BeeGFS Header Magic".to_string()
    } else if payload.len() >= 4 {
        let msg_type = u16::from_le_bytes([payload[0], payload[1]]);
        let name = match msg_type {
            1 => "Storage Read/Write",
            2 => "Metadata Operation",
            3 => "Management Heartbeat",
            4 => "Client Session",
            _ => "Message",
        };
        format!("BeeGFS {name}")
    } else {
        format!("BeeGFS ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::BeeFs,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_beegfs_magic() {
        let r = dissect_beegfs(None, None, 40000, 8003, b"BGFS_DATA");
        assert_eq!(r.protocol, Protocol::BeeFs);
        assert_eq!(r.summary, "BeeGFS Header Magic");
    }

    #[test]
    fn test_beegfs_msg() {
        let r = dissect_beegfs(None, None, 40000, 8003, &[0x01, 0x00, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::BeeFs);
        assert_eq!(r.summary, "BeeGFS Storage Read/Write");
    }
}
