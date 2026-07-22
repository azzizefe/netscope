// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an IBM Systems Network Architecture (SNA / APPN) frame (EtherType 0x80D5 or LLC SAP 0x04/0x08/0x0C).
pub fn dissect_sna(payload: &[u8]) -> DissectedResult {
    let summary = if payload.len() >= 2 {
        let fid = payload[0] >> 4;
        let fid_str = match fid {
            0 => "FID0",
            1 => "FID1",
            2 => "FID2 (APPN)",
            3 => "FID3",
            4 => "FID4 (Virtual Route)",
            5 => "FID5",
            _ => "SNA Path Control",
        };
        format!("IBM SNA / APPN {fid_str}")
    } else {
        format!("IBM SNA ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Sna,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sna_fid2() {
        let payload = vec![0x20, 0x00, 0x01];
        let r = dissect_sna(&payload);
        assert_eq!(r.protocol, Protocol::Sna);
        assert_eq!(r.summary, "IBM SNA / APPN FID2 (APPN)");
    }
}
