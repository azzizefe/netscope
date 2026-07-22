// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect HDFS Data Transfer Protocol (DataNode TCP 50010).
pub fn dissect_hdfs_data(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 3 {
        let opcode = payload[2];
        let op_str = match opcode {
            80 => "READ_BLOCK",
            81 => "WRITE_BLOCK",
            82 => "REPLACE_BLOCK",
            83 => "COPY_BLOCK",
            84 => "BLOCK_CHECKSUM",
            85 => "TRANSFER_BLOCK",
            86 => "REQUEST_SHORT_CIRCUIT_FDS",
            87 => "RELEASE_SHORT_CIRCUIT_FDS",
            _ => "Op",
        };
        format!("HDFS Data Transfer {op_str}")
    } else {
        format!("HDFS Data Transfer ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::HdfsData,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hdfs_read_block() {
        let payload = vec![0x00, 0x1C, 80]; // Version 28, READ_BLOCK
        let r = dissect_hdfs_data(None, None, 40000, 50010, &payload);
        assert_eq!(r.protocol, Protocol::HdfsData);
        assert_eq!(r.summary, "HDFS Data Transfer READ_BLOCK");
    }

    #[test]
    fn test_hdfs_short() {
        let r = dissect_hdfs_data(None, None, 40000, 50010, &[0x00]);
        assert_eq!(r.protocol, Protocol::HdfsData);
        assert!(r.summary.contains("1 B"));
    }
}
