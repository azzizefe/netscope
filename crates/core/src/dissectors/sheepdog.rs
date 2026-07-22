// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect Sheepdog distributed block storage messages (TCP 7000).
pub fn dissect_sheepdog(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 2 {
        let proto_flag = payload[0];
        let opcode = payload[1];
        let op_name = match opcode {
            0x01 => "CREATE_AND_WRITE",
            0x02 => "READ",
            0x03 => "WRITE",
            0x41 => "GET_NODE_LIST",
            0x42 => "NEW_VDI",
            0x43 => "DEL_VDI",
            0x44 => "GET_VDI_INFO",
            0x45 => "READ_VDIS",
            0x81 => "STAT_CLUSTER",
            _ => "Op",
        };
        let dir = if proto_flag == 0x80 { "Request" } else { "Response" };
        format!("Sheepdog {dir} · {op_name}")
    } else {
        format!("Sheepdog ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Sheepdog,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sheepdog_req() {
        let payload = vec![0x80, 0x02, 0x00, 0x00]; // Request READ
        let r = dissect_sheepdog(None, None, 40000, 7000, &payload);
        assert_eq!(r.protocol, Protocol::Sheepdog);
        assert_eq!(r.summary, "Sheepdog Request · READ");
    }
}
