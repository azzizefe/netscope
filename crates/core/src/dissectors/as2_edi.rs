// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect AS2 EDI Protocol (TCP 8080 / 8443).
pub fn dissect_as2_edi(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.contains(&b"AS2-To:") || payload.contains(&b"AS2-From:") || payload.contains(&b"as2-version:") {
        "AS2 EDI message".to_string()
    } else {
        format!("AS2 EDI ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::As2Edi,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as2_test() {
        let r = dissect_as2_edi(None, None, 40000, 8080, b"POST /as2 HTTP/1.1\r\nAS2-To: partnerX\r\nAS2-From: companyY\r\n");
        assert_eq!(r.protocol, Protocol::As2Edi);
        assert_eq!(r.summary, "AS2 EDI message");
    }
}
