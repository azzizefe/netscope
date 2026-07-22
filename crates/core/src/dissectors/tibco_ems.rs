// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect TIBCO EMS protocol (TCP 7222).
pub fn dissect_tibco_ems(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = format!("TIBCO EMS ({})", super::bytes(payload.len() as u64));

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TibcoEms,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tibco_ems_test() {
        let r = dissect_tibco_ems(None, None, 40000, 7222, b"\x00\x00\x00\x04");
        assert_eq!(r.protocol, Protocol::TibcoEms);
    }
}
