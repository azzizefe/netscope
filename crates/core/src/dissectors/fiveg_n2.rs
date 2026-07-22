// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_fiveg_n2(src_ip: Option<IpAddr>, dst_ip: Option<IpAddr>, src_port: u16, dst_port: u16, payload: &[u8]) -> DissectedResult {
    DissectedResult { src_addr: src_ip, dst_addr: dst_ip, src_port: Some(src_port), dst_port: Some(dst_port), protocol: Protocol::FivegN2, summary: format!("5G N2 NGAP ({})", super::bytes(payload.len() as u64)) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn fiveg_n2_test() { assert_eq!(dissect_fiveg_n2(None, None, 40000, 38412, b"\x00\x0F").protocol, Protocol::FivegN2); }
}
