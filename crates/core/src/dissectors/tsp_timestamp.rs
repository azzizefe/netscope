// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a TSP (RFC 3161 Time-Stamp Protocol over HTTP / TCP 318) message.
pub fn dissect_tsp_timestamp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.is_empty() {
        format!("TSP Timestamp ({})", super::bytes(0u64))
    } else {
        let text = String::from_utf8_lossy(payload);
        if text.contains("application/timestamp-query") {
            "TSP Time-Stamp Request (TimeStampReq)".to_string()
        } else if text.contains("application/timestamp-reply") {
            "TSP Time-Stamp Response (TimeStampResp)".to_string()
        } else {
            format!("TSP Time-Stamp Token ({})", super::bytes(payload.len() as u64))
        }
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TspTimestamp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tsp_query() {
        let payload = b"POST /tsa HTTP/1.1\r\nContent-Type: application/timestamp-query\r\n";
        let res = dissect_tsp_timestamp(None, None, 318, 318, payload);
        assert_eq!(res.protocol, Protocol::TspTimestamp);
        assert!(res.summary.contains("TimeStampReq"));
    }

    #[test]
    fn test_tsp_empty_payload() {
        let payload = vec![];
        let res = dissect_tsp_timestamp(None, None, 318, 318, &payload);
        assert_eq!(res.protocol, Protocol::TspTimestamp);
        assert!(res.summary.contains("TSP Timestamp (0 bytes)"));
    }
}
