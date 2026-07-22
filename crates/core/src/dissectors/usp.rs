// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect TR-369 / USP (User Services Platform protocol over WebSockets / STOMP / CoAP).
pub fn dissect_usp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if let Ok(s) = std::str::from_utf8(payload) {
        if s.contains("\"header\"") && s.contains("\"msg_type\"") {
            "TR-369 USP Record (JSON)".into()
        } else if s.contains("usp.msg") || s.contains("usp.Record") {
            "TR-369 USP Message".into()
        } else {
            format!("TR-369 USP Record ({})", super::bytes(payload.len() as u64))
        }
    } else if payload.len() >= 2 {
        format!("TR-369 USP Record ({})", super::bytes(payload.len() as u64))
    } else {
        format!("TR-369 USP ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Usp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_usp_record() {
        let payload = b"{\"header\":{\"msg_id\":\"123\",\"msg_type\":\"GET\"}}";
        let r = dissect_usp(None, None, 40000, 5683, payload);
        assert_eq!(r.protocol, Protocol::Usp);
        assert_eq!(r.summary, "TR-369 USP Record (JSON)");
    }
}
