// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Riak protocol-buffers message (TCP 8087) — the binary client
/// interface of the Riak distributed key-value store. Each frame is a 4-byte
/// big-endian length followed by a one-byte message code.
pub fn dissect_riak(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.get(4) {
        Some(&code) => {
            let name = match code {
                0 => "Error response",
                1 => "Ping request",
                2 => "Ping response",
                7 => "GetBucket",
                9 => "Get request",
                10 => "Get response",
                11 => "Put request",
                12 => "Put response",
                13 => "Delete request",
                17 => "ListKeys",
                _ => "message",
            };
            format!("Riak {name}")
        }
        None => format!("Riak ({} bytes)", payload.len()),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Riak,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_request() {
        let mut p = 30u32.to_be_bytes().to_vec();
        p.push(11); // Put request
        let r = dissect_riak(None, None, 40000, 8087, &p);
        assert_eq!(r.protocol, Protocol::Riak);
        assert_eq!(r.summary, "Riak Put request");
    }
}
