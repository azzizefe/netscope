// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_isa100_11a(src_ip: Option<IpAddr>, dst_ip: Option<IpAddr>, src_port: u16, dst_port: u16, payload: &[u8]) -> DissectedResult {
    DissectedResult { src_addr: src_ip, dst_addr: dst_ip, src_port: Some(src_port), dst_port: Some(dst_port), protocol: Protocol::Isa10011a, summary: format!("ISA100.11a Automation ({})", super::bytes(payload.len() as u64)) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn isa100_test() { assert_eq!(dissect_isa100_11a(None, None, 40000, 24130, b"\x49\x53").protocol, Protocol::Isa10011a); }
}
