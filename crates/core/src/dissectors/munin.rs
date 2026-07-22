// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect Munin Node Protocol (TCP 4949).
pub fn dissect_munin(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"# munin node at") {
        "Munin node banner".to_string()
    } else if payload.starts_with(b"fetch ") {
        "Munin fetch command".to_string()
    } else {
        format!("Munin Node ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Munin,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn munin_test() {
        let r = dissect_munin(None, None, 40000, 4949, b"# munin node at server01\n");
        assert_eq!(r.protocol, Protocol::Munin);
        assert!(r.summary.contains("banner"));
    }
}
