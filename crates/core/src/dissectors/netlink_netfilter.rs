// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect a NETLINK-NETFILTER packet.
pub fn dissect_netlink_netfilter(
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
        protocol: Protocol::NetlinkNetfilter,
        summary: format!("NETLINK-NETFILTER ({})", super::bytes(payload.len() as u64)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netlink_netfilter() {
        let r = dissect_netlink_netfilter(None, None, 0, 0, b"\x00\x01");
        assert_eq!(r.protocol, Protocol::NetlinkNetfilter);
    }
}
