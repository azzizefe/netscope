// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect Nagios NSCA Passive Check Protocol (TCP 5667).
pub fn dissect_nagios_nsca(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = format!("Nagios NSCA ({})", super::bytes(payload.len() as u64));

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::NagiosNsca,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nagios_nsca_test() {
        let r = dissect_nagios_nsca(None, None, 40000, 5667, b"\x00\x00\x00\x04");
        assert_eq!(r.protocol, Protocol::NagiosNsca);
    }
}
