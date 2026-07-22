// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an SS7 MTP Level 2 (Message Transfer Part Level 2 — ITU-T Q.703) frame.
pub fn dissect_mtp2(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 3 {
        format!("MTP2 ({})", super::bytes(payload.len() as u64))
    } else {
        let bsn = payload[0] & 0x7F;
        let bib = (payload[0] & 0x80) >> 7;
        let fsn = payload[1] & 0x7F;
        let fib = (payload[1] & 0x80) >> 7;
        let li = payload[2] & 0x3F;

        let unit_type = match li {
            0 => "FISU (Fill-In Signal Unit)",
            1 | 2 => "LSSU (Link Status Signal Unit)",
            _ => "MSU (Message Signal Unit)",
        };

        format!("SS7 MTP2 {unit_type} — BSN {bsn} (BIB {bib}), FSN {fsn} (FIB {fib})")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Mtp2,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mtp2_msu() {
        // BSN = 10, BIB = 1 (0x8A), FSN = 12, FIB = 1 (0x8C), LI = 5 (MSU)
        let payload = vec![0x8A, 0x8C, 0x05, 0x00];
        let res = dissect_mtp2(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Mtp2);
        assert!(res.summary.contains("MSU (Message Signal Unit)"));
        assert!(res.summary.contains("BSN 10"));
        assert!(res.summary.contains("FSN 12"));
    }

    #[test]
    fn test_mtp2_short_payload() {
        let payload = vec![0x01, 0x02];
        let res = dissect_mtp2(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Mtp2);
        assert!(res.summary.contains("MTP2 (2 bytes)"));
    }
}
