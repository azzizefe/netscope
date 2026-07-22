// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect Gemini Hypertext Protocol (TCP 1965).
pub fn dissect_gemini_proto(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"gemini://") {
        "Gemini request URL".to_string()
    } else if payload.len() >= 2 && payload[0].is_ascii_digit() && payload[1].is_ascii_digit() {
        "Gemini response status".to_string()
    } else {
        format!("Gemini Protocol ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::GeminiProto,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gemini_test() {
        let r = dissect_gemini_proto(None, None, 40000, 1965, b"gemini://geminispace.info/\r\n");
        assert_eq!(r.protocol, Protocol::GeminiProto);
        assert_eq!(r.summary, "Gemini request URL");
    }
}
