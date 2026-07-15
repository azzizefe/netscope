// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Kafka segment (TCP 9092).
pub fn dissect_kafka(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 12 {
        let size = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let api_key = u16::from_be_bytes([payload[4], payload[5]]);
        let api_ver = u16::from_be_bytes([payload[6], payload[7]]);
        format!("Kafka Message — Size {}, API Key {}, Version {}", size, api_key, api_ver)
    } else {
        "Kafka MQ Traffic".to_string()
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Kafka,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kafka_basic() {
        let mut pkt = vec![0u8; 12];
        pkt[0..4].copy_from_slice(&100u32.to_be_bytes()); // size
        pkt[4..6].copy_from_slice(&18u16.to_be_bytes());  // api key
        pkt[6..8].copy_from_slice(&3u16.to_be_bytes());   // version
        let r = dissect_kafka(None, None, 50000, 9092, &pkt);
        assert_eq!(r.protocol, Protocol::Kafka);
        assert!(r.summary.contains("Size 100, API Key 18, Version 3"));
    }
}
