// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect collectd binary v5 extensions (UDP 25826).
pub fn dissect_collectd_v5(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = format!("collectd v5 binary ({})", super::bytes(payload.len() as u64));

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::CollectdV5,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collectd_v5_test() {
        let r = dissect_collectd_v5(None, None, 40000, 25826, b"\x00\x00\x00\x09host");
        assert_eq!(r.protocol, Protocol::CollectdV5);
    }
}
