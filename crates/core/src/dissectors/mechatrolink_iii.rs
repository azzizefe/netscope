// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_mechatrolink_iii(src_ip: Option<IpAddr>, dst_ip: Option<IpAddr>, src_port: u16, dst_port: u16, payload: &[u8]) -> DissectedResult {
    DissectedResult { src_addr: src_ip, dst_addr: dst_ip, src_port: Some(src_port), dst_port: Some(dst_port), protocol: Protocol::MechatrolinkIii, summary: format!("MECHATROLINK-III Motion ({})", super::bytes(payload.len() as u64)) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn mechatrolink_test() { assert_eq!(dissect_mechatrolink_iii(None, None, 0, 0, b"\x88\xE3\x00").protocol, Protocol::MechatrolinkIii); }
}
