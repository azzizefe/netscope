// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect Web Proxy Auto-Discovery Protocol (WPAD) (TCP 80 / 3128).
pub fn dissect_wpad(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"GET /wpad.dat") || payload.starts_with(b"GET /proxy.pac") {
        "WPAD proxy auto-config request".to_string()
    } else {
        format!("WPAD ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Wpad,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wpad_test() {
        let r = dissect_wpad(None, None, 40000, 80, b"GET /wpad.dat HTTP/1.1\r\n");
        assert_eq!(r.protocol, Protocol::Wpad);
        assert_eq!(r.summary, "WPAD proxy auto-config request");
    }
}
