// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect a Cisco FP-MiM packet.
pub fn dissect_cisco_fp_mim(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::CiscoFpMim,
        summary: format!("Cisco FP-MiM ({})", super::bytes(payload.len() as u64)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cisco_fp_mim() {
        let r = dissect_cisco_fp_mim(None, None, 0, 0, b"\x00\x01");
        assert_eq!(r.protocol, Protocol::CiscoFpMim);
    }
}