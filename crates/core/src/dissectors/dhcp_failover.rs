// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 azzizefe. All rights reserved.

use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

/// Dissect a DHCP Failover packet.
pub fn dissect_dhcp_failover(
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
        protocol: Protocol::DhcpFailover,
        summary: format!("DHCP Failover ({})", super::bytes(payload.len() as u64)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dhcp_failover() {
        let r = dissect_dhcp_failover(None, None, 0, 0, b"\x00\x01");
        assert_eq!(r.protocol, Protocol::DhcpFailover);
    }
}
