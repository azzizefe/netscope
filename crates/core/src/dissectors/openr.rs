// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an OpenR (Facebook OpenRouting protocol over ZeroMQ / UDP 6683) packet.
pub fn dissect_openr(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.is_empty() {
        format!("OpenR ({})", super::bytes(0u64))
    } else {
        let msg_str = String::from_utf8_lossy(payload);
        if msg_str.contains("spark") || msg_str.contains("Spark") {
            "OpenR Spark Hello".to_string()
        } else if msg_str.contains("kvstore") || msg_str.contains("KvStore") {
            "OpenR KvStore Sync".to_string()
        } else if msg_str.contains("link-monitor") {
            "OpenR LinkMonitor Update".to_string()
        } else {
            format!("OpenR Packet ({})", super::bytes(payload.len() as u64))
        }
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Openr,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openr_spark_hello() {
        let payload = b"openr-spark-v1-hello";
        let res = dissect_openr(None, None, 6683, 6683, payload);
        assert_eq!(res.protocol, Protocol::Openr);
        assert!(res.summary.contains("Spark Hello"));
    }

    #[test]
    fn test_openr_empty_payload() {
        let payload = vec![];
        let res = dissect_openr(None, None, 6683, 6683, &payload);
        assert_eq!(res.protocol, Protocol::Openr);
        assert!(res.summary.contains("OpenR (0 bytes)"));
    }
}
