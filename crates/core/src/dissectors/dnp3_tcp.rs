// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_dnp3_tcp(src_ip: Option<IpAddr>, dst_ip: Option<IpAddr>, src_port: u16, dst_port: u16, payload: &[u8]) -> DissectedResult {
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Dnp3Tcp,
        summary: format!("Dnp3Tcp ({})", super::bytes(payload.len() as u64)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_dnp3_tcp() {
        let r = dissect_dnp3_tcp(None, None, 0, 0, b"\x00\x01");
        assert_eq!(r.protocol, Protocol::Dnp3Tcp);
    }
}