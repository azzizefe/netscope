// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect NoMachine NX Remote Desktop Protocol (TCP 4000).
pub fn dissect_nomachine_nx(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"NXPROXY-") || payload.starts_with(b"NX") {
        "NoMachine NX handshake".to_string()
    } else {
        format!("NoMachine NX ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::NomachineNx,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nomachine_nx_test() {
        let r = dissect_nomachine_nx(None, None, 40000, 4000, b"NXPROXY-3.5.0\n");
        assert_eq!(r.protocol, Protocol::NomachineNx);
        assert_eq!(r.summary, "NoMachine NX handshake");
    }
}
