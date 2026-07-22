// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect Fibre Channel Protocol (FCP) for SCSI (FCP_CMND, FCP_DATA, FCP_RSP, FCP_XFER_RDY).
pub fn dissect_fcp(payload: &[u8]) -> DissectedResult {
    if payload.len() < 4 {
        return DissectedResult {
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
            protocol: Protocol::Fcp,
            summary: format!("FCP ({})", super::bytes(payload.len() as u64)),
        };
    }

    // FCP Command IU starts with 8-byte LUN, 1-byte CRN, 1-byte task attribute, 1-byte task mgmt, 1-byte add_cdb_len, followed by CDB.
    let summary = if payload.len() >= 12 {
        let scsi_op = payload[12];
        let op_name = match scsi_op {
            0x00 => "TEST UNIT READY",
            0x08 => "READ(6)",
            0x0A => "WRITE(6)",
            0x12 => "INQUIRY",
            0x1A => "MODE SENSE",
            0x25 => "READ CAPACITY",
            0x28 => "READ(10)",
            0x2A => "WRITE(10)",
            _ => "SCSI Command",
        };
        format!("FCP_CMND · {op_name}")
    } else {
        format!("FCP Information Unit ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Fcp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fcp_cmnd() {
        let mut p = vec![0u8; 12];
        p.push(0x12); // INQUIRY
        let r = dissect_fcp(&p);
        assert_eq!(r.protocol, Protocol::Fcp);
        assert_eq!(r.summary, "FCP_CMND · INQUIRY");
    }

    #[test]
    fn test_fcp_short() {
        let r = dissect_fcp(&[0x01, 0x02]);
        assert_eq!(r.protocol, Protocol::Fcp);
        assert!(r.summary.contains("2 bytes"));
    }
}
