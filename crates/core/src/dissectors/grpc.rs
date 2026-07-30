// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors

use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_grpc(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let text = String::from_utf8_lossy(&payload[..payload.len().min(512)]);
    let method = text.lines().find_map(|l| {
        if l.contains("path:") || l.starts_with('/') {
            let p = l.split_whitespace().last().unwrap_or(l);
            if p.contains('/') {
                Some(p.trim_matches(':').to_string())
            } else {
                None
            }
        } else {
            None
        }
    });

    let summary = if let Some(path) = method {
        format!("gRPC Path: {path}")
    } else {
        format!("gRPC HTTP/2 ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Grpc,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grpc() {
        let r = dissect_grpc(None, None, 0, 0, b"\x00\x01");
        assert_eq!(r.protocol, Protocol::Grpc);
    }
}
