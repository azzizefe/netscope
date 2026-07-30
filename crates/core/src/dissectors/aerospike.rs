// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an Aerospike message (TCP 3000) — the client protocol for the
/// low-latency key-value database. The proto header is version(1), type(1),
/// then a 6-byte size.
pub fn dissect_aerospike(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.get(1) {
        Some(&t) => {
            let name = match t {
                1 => "Info",
                3 => "Message (AS_MSG)",
                4 => "Compressed message",
                _ => "message",
            };
            format!("Aerospike {name}")
        }
        None => "Aerospike (truncated)".to_string(),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Aerospike,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_message() {
        // version 2, type 1 (Info).
        let r = dissect_aerospike(None, None, 40000, 3000, &[0x02, 0x01, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::Aerospike);
        assert_eq!(r.summary, "Aerospike Info");
    }
}
