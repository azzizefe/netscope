// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect HP Vertica wire protocol (TCP 5433).
pub fn dissect_vertica(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 4 && &payload[..4] == b"Q\x00\x00\x00" || (!payload.is_empty() && payload[0] == b'Q') {
        "Vertica Query".to_string()
    } else {
        format!("Vertica client protocol ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Vertica,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vertica_query() {
        let r = dissect_vertica(None, None, 40000, 5433, b"Q\x00\x00\x10SELECT 1");
        assert_eq!(r.protocol, Protocol::Vertica);
        assert!(r.summary.contains("Query"));
    }
}
