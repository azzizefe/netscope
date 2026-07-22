// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect Solace SMF Protocol (TCP 55555).
pub fn dissect_solace_smf(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = format!("Solace SMF ({})", super::bytes(payload.len() as u64));

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SolaceSmf,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solace_test() {
        let r = dissect_solace_smf(None, None, 40000, 55555, b"\x00\x00\x00\x04");
        assert_eq!(r.protocol, Protocol::SolaceSmf);
    }
}
