// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect Tarantool iproto binary protocol message (TCP 3301).
pub fn dissect_tarantool(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 5 && (payload.starts_with(b"Tarantool") || payload.starts_with(b"tarantool")) {
        "Tarantool iproto greeting".to_string()
    } else {
        format!("Tarantool iproto ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Tarantool,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tarantool_greeting() {
        let r = dissect_tarantool(None, None, 40000, 3301, b"Tarantool 2.10.0 (Binary)");
        assert_eq!(r.protocol, Protocol::Tarantool);
        assert!(r.summary.contains("greeting"));
    }
}
