// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect NNG / nanomsg Scalability Protocols (TCP 5554).
pub fn dissect_nanomsg_sp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"\x00SP\x00") || payload.starts_with(b"SP") {
        "nanomsg SP header".to_string()
    } else {
        format!("nanomsg SP ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::NanomsgSp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nanomsg_test() {
        let r = dissect_nanomsg_sp(None, None, 40000, 5554, b"\x00SP\x00\x00\x10");
        assert_eq!(r.protocol, Protocol::NanomsgSp);
        assert!(r.summary.contains("header"));
    }
}
