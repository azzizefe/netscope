// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an SMB/SMB2 segment (TCP 445).
pub fn dissect_smb(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let mut is_smb = false;
    let mut is_smb2 = false;
    if payload.len() >= 4 {
        if &payload[..4] == b"\xFFSMB" {
            is_smb = true;
        } else if &payload[..4] == b"\xFESMB" {
            is_smb2 = true;
        } else if payload.len() >= 8
            && (&payload[4..8] == b"\xFFSMB" || &payload[4..8] == b"\xFESMB")
        {
            if &payload[4..8] == b"\xFFSMB" {
                is_smb = true;
            } else {
                is_smb2 = true;
            }
        }
    }
    let summary = if is_smb2 {
        "SMB2/SMB3 Protocol Traffic".to_string()
    } else if is_smb {
        "SMB1 Protocol Traffic".to_string()
    } else {
        "SMB Protocol Traffic".to_string()
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Smb,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smb2_detection() {
        let pkt = [0x00, 0x00, 0x00, 0x40, 0xFE, 0x53, 0x4D, 0x42];
        let r = dissect_smb(None, None, 50000, 445, &pkt);
        assert_eq!(r.protocol, Protocol::Smb);
        assert!(r.summary.contains("SMB2"));
    }
}
