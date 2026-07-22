// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_fiveg_n4(src_ip: Option<IpAddr>, dst_ip: Option<IpAddr>, src_port: u16, dst_port: u16, payload: &[u8]) -> DissectedResult {
    DissectedResult { src_addr: src_ip, dst_addr: dst_ip, src_port: Some(src_port), dst_port: Some(dst_port), protocol: Protocol::FivegN4, summary: format!("5G N4 PFCP ({})", super::bytes(payload.len() as u64)) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn fiveg_n4_test() { assert_eq!(dissect_fiveg_n4(None, None, 40000, 8805, b"\x20\x01").protocol, Protocol::FivegN4); }
}
