// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect OrangeFS / PVFS2 storage protocol messages (TCP 3334).
pub fn dissect_orangefs(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 8 {
        let magic = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let op = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let op_name = match op {
            1 => "CREATE",
            2 => "REMOVE",
            3 => "IO",
            4 => "GETATTR",
            5 => "SETATTR",
            6 => "LOOKUP",
            7 => "READDIR",
            _ => "Request",
        };
        if magic == 0xEAEA_1010 || magic == 0x3334_0001 {
            format!("OrangeFS {op_name}")
        } else {
            format!("OrangeFS Operation {op}")
        }
    } else {
        format!("OrangeFS ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::OrangeFs,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orangefs_io() {
        let payload = vec![0xEA, 0xEA, 0x10, 0x10, 0x00, 0x00, 0x00, 0x03];
        let r = dissect_orangefs(None, None, 40000, 3334, &payload);
        assert_eq!(r.protocol, Protocol::OrangeFs);
        assert_eq!(r.summary, "OrangeFS IO");
    }
}
