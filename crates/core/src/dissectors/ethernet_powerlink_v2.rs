// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_ethernet_powerlink_v2(src_ip: Option<IpAddr>, dst_ip: Option<IpAddr>, src_port: u16, dst_port: u16, payload: &[u8]) -> DissectedResult {
    DissectedResult { src_addr: src_ip, dst_addr: dst_ip, src_port: Some(src_port), dst_port: Some(dst_port), protocol: Protocol::EthernetPowerlinkV2, summary: format!("POWERLINK v2 ({})", super::bytes(payload.len() as u64)) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn powerlink_v2_test() { assert_eq!(dissect_ethernet_powerlink_v2(None, None, 0, 0, b"\x88\xAB\x01").protocol, Protocol::EthernetPowerlinkV2); }
}
