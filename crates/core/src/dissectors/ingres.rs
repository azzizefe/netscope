// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect Actian Ingres GCA protocol (TCP 21071 / 1783).
pub fn dissect_ingres(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = format!("Ingres GCA ({})", super::bytes(payload.len() as u64));

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ingres,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingres_test() {
        let r = dissect_ingres(None, None, 40000, 21071, b"\x00\x00\x00\x04");
        assert_eq!(r.protocol, Protocol::Ingres);
    }
}
