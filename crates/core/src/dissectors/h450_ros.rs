// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect an H450-ROS (ITU-T H.450 Remote Operations Service) packet.
pub fn dissect_h450_ros(
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
        protocol: Protocol::H450Ros,
        summary: format!("H450Ros ({})", super::bytes(payload.len() as u64)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_h450_ros() {
        let r = dissect_h450_ros(None, None, 0, 0, b"\x00\x01");
        assert_eq!(r.protocol, Protocol::H450Ros);
    }
}
