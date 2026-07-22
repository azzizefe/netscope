// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an Extreme Networks Discovery Protocol (EDP, UDP 6112 or EtherType 0x00E0) frame.
pub fn dissect_edp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 4 {
        let version = payload[0];
        format!("Extreme EDP v{version} Announcement ({})", super::bytes(payload.len() as u64))
    } else {
        format!("Extreme EDP ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Edp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edp_announcement() {
        let payload = vec![0x01, 0x00, 0x00, 0x10];
        let r = dissect_edp(None, None, 6112, 6112, &payload);
        assert_eq!(r.protocol, Protocol::Edp);
        assert!(r.summary.contains("Extreme EDP v1"));
    }
}
