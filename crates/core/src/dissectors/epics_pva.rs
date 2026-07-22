// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect EPICS pvAccess (TCP/UDP 5075).
pub fn dissect_epics_pva(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"\xCA") || payload.len() >= 8 {
        "EPICS pvAccess message".to_string()
    } else {
        format!("EPICS pvAccess ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::EpicsPva,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epics_pva_test() {
        let r = dissect_epics_pva(None, None, 40000, 5075, b"\xCA\x01\x00\x00\x00\x00\x00\x08");
        assert_eq!(r.protocol, Protocol::EpicsPva);
        assert_eq!(r.summary, "EPICS pvAccess message");
    }
}
