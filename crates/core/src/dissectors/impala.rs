// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect Impala query service / Beeswax protocol (TCP 21000 / 21050).
pub fn dissect_impala(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = format!("Impala Thrift Query ({})", super::bytes(payload.len() as u64));

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Impala,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn impala_test() {
        let r = dissect_impala(None, None, 40000, 21000, b"\x80\x01\x00\x01");
        assert_eq!(r.protocol, Protocol::Impala);
    }
}
