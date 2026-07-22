// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect PMIx Process Management Interface Exascale (TCP/UDS 6120).
pub fn dissect_pmix(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = format!("PMIx Exascale ({})", super::bytes(payload.len() as u64));

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Pmix,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pmix_test() {
        let r = dissect_pmix(None, None, 40000, 6120, b"pmix\x00\x01\x00\x00");
        assert_eq!(r.protocol, Protocol::Pmix);
    }
}
