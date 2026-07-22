// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Check if the payload looks like an SRP (SCSI RDMA Protocol) Information Unit.
pub(crate) fn looks_like_srp_rdma(payload: &[u8]) -> bool {
    if payload.len() < 4 {
        return false;
    }
    matches!(payload[0], 0x00..=0x09)
}

/// Dissect a SCSI RDMA Protocol (SRP, INCITS 365-2002 / T10 SRP) message.
pub fn dissect_srp_rdma(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.first() {
        Some(&iu_type) => {
            let name = match iu_type {
                0x00 => "SRP Login Request",
                0x01 => "SRP Login Response",
                0x02 => "SRP Login Reject",
                0x03 => "SRP Initiator Logout",
                0x04 => "SRP Target Logout",
                0x05 => "SRP Task Management",
                0x06 => "SRP Command",
                0x07 => "SRP Response",
                0x08 => "SRP AER Request",
                0x09 => "SRP AER Response",
                _ => "SRP Information Unit",
            };
            format!("{name} ({})", super::bytes(payload.len() as u64))
        }
        None => format!("SRP RDMA ({})", super::bytes(0u64)),
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SrpRdma,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srp_cmd() {
        let payload = vec![0x06, 0x00, 0x00, 0x00, 0x12, 0x34];
        assert!(looks_like_srp_rdma(&payload));
        let res = dissect_srp_rdma(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::SrpRdma);
        assert!(res.summary.contains("SRP Command"));
    }

    #[test]
    fn test_srp_empty() {
        let payload = vec![];
        assert!(!looks_like_srp_rdma(&payload));
        let res = dissect_srp_rdma(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::SrpRdma);
        assert!(res.summary.contains("SRP RDMA (0 bytes)"));
    }
}
