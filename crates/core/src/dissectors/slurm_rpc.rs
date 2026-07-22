// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect Slurm Workload Manager RPC (TCP 6817 / 6818).
pub fn dissect_slurm_rpc(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 10 {
        let length = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let msg_type = u16::from_be_bytes([payload[4], payload[5]]);
        format!("Slurm RPC type 0x{:04X} (len {})", msg_type, length)
    } else {
        format!("Slurm RPC ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SlurmRpc,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slurm_rpc_test() {
        let r = dissect_slurm_rpc(None, None, 40000, 6817, b"\x00\x00\x00\x20\x10\x01\x00\x00\x00\x00");
        assert_eq!(r.protocol, Protocol::SlurmRpc);
        assert!(r.summary.contains("Slurm RPC type"));
    }
}
