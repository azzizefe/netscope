// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a ZooKeeper message (TCP 2181) — the coordination service Kafka,
/// HBase and friends use for leader election and config. Each frame is a
/// 4-byte length, then a transaction id (xid) and an opcode.
pub fn dissect_zookeeper(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 12 {
        let xid = i32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let op = i32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
        // Negative xids are protocol-level, not application requests.
        match xid {
            -2 => "ZooKeeper ping".to_string(),
            -4 => "ZooKeeper auth".to_string(),
            -8 => "ZooKeeper set watches".to_string(),
            _ => {
                let name = match op {
                    0 => "notification",
                    1 => "create",
                    2 => "delete",
                    3 => "exists",
                    4 => "getData",
                    5 => "setData",
                    8 => "getChildren",
                    11 => "ping",
                    -11 => "close session",
                    _ => "request",
                };
                format!("ZooKeeper {name}")
            }
        }
    } else {
        format!("ZooKeeper ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Zookeeper,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_data() {
        let mut p = 12u32.to_be_bytes().to_vec(); // frame length
        p.extend_from_slice(&1i32.to_be_bytes()); // xid
        p.extend_from_slice(&4i32.to_be_bytes()); // opcode: getData
        let r = dissect_zookeeper(None, None, 40000, 2181, &p);
        assert_eq!(r.protocol, Protocol::Zookeeper);
        assert_eq!(r.summary, "ZooKeeper getData");
    }

    #[test]
    fn ping_uses_the_reserved_xid() {
        let mut p = 8u32.to_be_bytes().to_vec();
        p.extend_from_slice(&(-2i32).to_be_bytes());
        p.extend_from_slice(&11i32.to_be_bytes());
        let r = dissect_zookeeper(None, None, 40000, 2181, &p);
        assert_eq!(r.summary, "ZooKeeper ping");
    }
}
