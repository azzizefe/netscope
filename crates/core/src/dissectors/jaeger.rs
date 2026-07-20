// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Jaeger agent message (UDP 6831) — distributed tracing spans an
/// instrumented service emits to its local Jaeger agent. The payload is Thrift;
/// the compact protocol identifies itself with a leading 0x82.
pub fn dissect_jaeger(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.first() {
        Some(0x82) => "Jaeger spans (Thrift compact)".to_string(),
        Some(0x80) => "Jaeger spans (Thrift binary)".to_string(),
        _ => format!("Jaeger trace data ({})", super::bytes(payload.len() as u64)),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Jaeger,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_thrift() {
        let r = dissect_jaeger(None, None, 40000, 6831, &[0x82, 0x21, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Jaeger);
        assert!(r.summary.contains("Thrift compact"), "{}", r.summary);
    }
}
