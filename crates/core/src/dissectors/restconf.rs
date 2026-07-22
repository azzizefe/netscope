// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect RESTCONF Protocol (TCP 8080 / 443).
pub fn dissect_restconf(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"GET /restconf") || payload.starts_with(b"POST /restconf") || payload.starts_with(b"PUT /restconf") {
        "RESTCONF request".to_string()
    } else {
        format!("RESTCONF ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Restconf,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restconf_test() {
        let r = dissect_restconf(None, None, 40000, 8080, b"GET /restconf/data/interfaces HTTP/1.1\r\n");
        assert_eq!(r.protocol, Protocol::Restconf);
        assert_eq!(r.summary, "RESTCONF request");
    }
}
