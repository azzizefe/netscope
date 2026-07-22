// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect GB/T 26982 Industrial Automation Control (TCP/UDP 20000).
pub fn dissect_gbt26982(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = format!("GB/T 26982 Industrial ({})", super::bytes(payload.len() as u64));

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Gbt26982,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gbt26982_test() {
        let r = dissect_gbt26982(None, None, 40000, 20000, b"\x68\x04\x00\x00");
        assert_eq!(r.protocol, Protocol::Gbt26982);
    }
}
