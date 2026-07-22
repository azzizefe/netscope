// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect Matrix Federation API Protocol (TCP 8448).
pub fn dissect_matrix_federation(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"GET /_matrix/federation/") || payload.starts_with(b"PUT /_matrix/federation/") {
        "Matrix federation request".to_string()
    } else {
        format!("Matrix Federation ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::MatrixFederation,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_test() {
        let r = dissect_matrix_federation(None, None, 40000, 8448, b"GET /_matrix/federation/v1/version HTTP/1.1\r\n");
        assert_eq!(r.protocol, Protocol::MatrixFederation);
        assert_eq!(r.summary, "Matrix federation request");
    }
}
