// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect TIBCO Rendezvous protocol (UDP 7500).
pub fn dissect_tibco_rv(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = format!("TIBCO Rendezvous ({})", super::bytes(payload.len() as u64));

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TibcoRv,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tibco_rv_test() {
        let r = dissect_tibco_rv(None, None, 40000, 7500, b"\x00\x01tibrv");
        assert_eq!(r.protocol, Protocol::TibcoRv);
    }
}
