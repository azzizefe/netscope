// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Lightweight M2M (LwM2M, OMA LwM2M over CoAP) payload.
pub fn dissect_lwm2m(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 2 {
        let content_type = u16::from_be_bytes([payload[0], payload[1]]);
        let ct_name = match content_type {
            11542 => "LwM2M TLV",
            11543 => "LwM2M JSON",
            310 => "LwM2M CBOR",
            110 => "LwM2M SenML JSON",
            112 => "LwM2M SenML CBOR",
            _ => "LwM2M Payload",
        };
        format!("OMA LwM2M {ct_name}")
    } else {
        format!("OMA LwM2M ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Lwm2m,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lwm2m_tlv() {
        let payload = vec![0xC8, 0x00, 0x01];
        let r = dissect_lwm2m(None, None, 5683, 5683, &payload);
        assert_eq!(r.protocol, Protocol::Lwm2m);
        assert!(r.summary.contains("OMA LwM2M"));
    }
}
