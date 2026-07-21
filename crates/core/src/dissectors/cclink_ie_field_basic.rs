// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use super::DissectedResult;
use crate::models::Protocol;

/// Dissect a CC-Link IE Field Network Basic message on UDP port 61450.
///
/// It uses SLMP/MELSEC 3E/4E framing for both cyclic and transient communication.
pub fn dissect_cclink_ie_field_basic(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = super::slmp::parse(payload).unwrap_or_else(|| {
        format!(
            "CC-Link IE Field Basic ({})",
            super::bytes(payload.len() as u64)
        )
    });

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::CcLinkIeFieldBasic,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cclink_basic_request() {
        // Build a mock SLMP 3E request: subheader=0x5000, net=1, station=2, timer=0, cmd=0x0401 (Read), sub=0
        let mut p = vec![];
        p.extend_from_slice(&0x5000u16.to_be_bytes()); // subheader
        p.push(1); // network
        p.push(2); // station
        p.extend_from_slice(&0x03FFu16.to_be_bytes()); // dest module io
        p.push(0); // dest station
        p.extend_from_slice(&10u16.to_le_bytes()); // length
        p.extend_from_slice(&0u16.to_le_bytes()); // timer
        p.extend_from_slice(&0x0401u16.to_le_bytes()); // cmd (Read)
        p.extend_from_slice(&0u16.to_le_bytes()); // subcommand

        let r = dissect_cclink_ie_field_basic(None, None, 61450, 61450, &p);
        assert_eq!(r.protocol, Protocol::CcLinkIeFieldBasic);
        assert!(r.summary.contains("SLMP Read"), "{}", r.summary);
    }
}
