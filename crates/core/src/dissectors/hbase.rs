// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect HBase RPC protocol (TCP 16000 / 16020).
pub fn dissect_hbase(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"HBas") {
        "HBase RPC connection header".to_string()
    } else {
        format!("HBase RPC ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Hbase,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hbase_header() {
        let r = dissect_hbase(None, None, 40000, 16000, b"HBas\x00\x50");
        assert_eq!(r.protocol, Protocol::Hbase);
        assert!(r.summary.contains("header"));
    }
}
