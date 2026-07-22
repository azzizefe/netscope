// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect Couchbase memcached binary extensions (TCP 11210).
pub fn dissect_couchbase(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 24 && (payload[0] == 0x80 || payload[0] == 0x81) {
        "Couchbase Memcached binary extension frame".to_string()
    } else {
        format!("Couchbase protocol ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Couchbase,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn couchbase_binary() {
        let mut buf = [0u8; 24];
        buf[0] = 0x80;
        let r = dissect_couchbase(None, None, 40000, 11210, &buf);
        assert_eq!(r.protocol, Protocol::Couchbase);
        assert!(r.summary.contains("Memcached"));
    }
}
