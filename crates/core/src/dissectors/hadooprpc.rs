// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Hadoop RPC message (TCP 8020) — how clients talk to the HDFS
/// NameNode and other Hadoop services. A connection opens with the "hrpc"
/// magic followed by the RPC version.
pub fn dissect_hadooprpc(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"hrpc") {
        match payload.get(4) {
            Some(v) => format!("Hadoop RPC handshake (v{v})"),
            None => "Hadoop RPC handshake".to_string(),
        }
    } else {
        format!("Hadoop RPC call ({} bytes)", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::HadoopRpc,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake() {
        let r = dissect_hadooprpc(None, None, 40000, 8020, b"hrpc\x09\x00\x00");
        assert_eq!(r.protocol, Protocol::HadoopRpc);
        assert_eq!(r.summary, "Hadoop RPC handshake (v9)");
    }
}
