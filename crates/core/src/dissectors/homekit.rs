// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect Apple HomeKit Accessory Protocol (HAP over HTTP / TLV8) frame.
pub fn dissect_homekit(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"POST /pair-setup") {
        "HomeKit HAP Pair Setup Request".into()
    } else if payload.starts_with(b"POST /pair-verify") {
        "HomeKit HAP Pair Verify Request".into()
    } else if payload.starts_with(b"GET /accessories") {
        "HomeKit HAP Get Accessories".into()
    } else if payload.starts_with(b"PUT /characteristics") {
        "HomeKit HAP Update Characteristics".into()
    } else if payload.starts_with(b"GET /characteristics") {
        "HomeKit HAP Read Characteristics".into()
    } else if payload.starts_with(b"HTTP/1.1 200 OK") || payload.starts_with(b"HTTP/1.1 204") {
        "HomeKit HAP Response".into()
    } else if payload.len() >= 2 {
        let tlv_tag = payload[0];
        let tlv_len = payload[1] as usize;
        format!("HomeKit HAP TLV8 (Tag 0x{tlv_tag:02X}, len {tlv_len})")
    } else {
        format!("HomeKit HAP ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::HomekitHap,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_homekit_pair_setup() {
        let payload = b"POST /pair-setup HTTP/1.1\r\nHost: hap.local\r\n\r\n";
        let r = dissect_homekit(None, None, 51827, 51827, payload);
        assert_eq!(r.protocol, Protocol::HomekitHap);
        assert_eq!(r.summary, "HomeKit HAP Pair Setup Request");
    }
}
