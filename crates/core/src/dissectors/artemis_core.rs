// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect ActiveMQ Artemis Core Protocol (TCP 61616).
pub fn dissect_artemis_core(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = format!("ActiveMQ Artemis Core ({})", super::bytes(payload.len() as u64));

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::ArtemisCore,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artemis_test() {
        let r = dissect_artemis_core(None, None, 40000, 61616, b"\x00\x00\x00\x10ARTEMIS");
        assert_eq!(r.protocol, Protocol::ArtemisCore);
    }
}
