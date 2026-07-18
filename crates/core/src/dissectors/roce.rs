// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a RoCE frame (EtherType 0x8915) — RDMA over Converged Ethernet,
/// which lets one machine read and write another's memory directly, bypassing
/// the kernel. Common in HPC and storage fabrics. Byte 0 of the InfiniBand
/// Base Transport Header is the opcode.
pub fn dissect_roce(payload: &[u8]) -> DissectedResult {
    let summary = match payload.first() {
        Some(&op) => {
            // The low 5 bits select the operation within a transport service.
            let name = match op & 0x1F {
                0x00 => "SEND First",
                0x02 => "SEND Last",
                0x04 => "SEND Only",
                0x06 => "RDMA WRITE First",
                0x0A => "RDMA WRITE Only",
                0x0C => "RDMA READ Request",
                0x0D => "RDMA READ Response",
                0x11 => "Acknowledge",
                _ => "operation",
            };
            format!("RoCE — InfiniBand {name}")
        }
        None => "RoCE (empty)".to_string(),
    };
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Roce,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdma_read_request() {
        let r = dissect_roce(&[0x0C, 0x40, 0xFF, 0xFF]);
        assert_eq!(r.protocol, Protocol::Roce);
        assert!(r.summary.contains("RDMA READ Request"), "{}", r.summary);
    }
}
