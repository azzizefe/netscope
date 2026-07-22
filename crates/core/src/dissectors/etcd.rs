// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect etcd v3 gRPC protocol (TCP 2379).
pub fn dissect_etcd(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = format!("etcd v3 gRPC ({})", super::bytes(payload.len() as u64));

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Etcd,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etcd_test() {
        let r = dissect_etcd(None, None, 40000, 2379, b"\x00\x00\x00\x00\x05etcd3");
        assert_eq!(r.protocol, Protocol::Etcd);
    }
}
