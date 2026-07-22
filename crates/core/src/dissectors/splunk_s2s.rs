// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect Splunk Server-to-Server (S2S) Protocol (TCP 9997).
pub fn dissect_splunk_s2s(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = format!("Splunk S2S ({})", super::bytes(payload.len() as u64));

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SplunkS2s,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splunk_s2s_test() {
        let r = dissect_splunk_s2s(None, None, 40000, 9997, b"\x00\x00\x00\x10--SPLUNK--");
        assert_eq!(r.protocol, Protocol::SplunkS2s);
    }
}
