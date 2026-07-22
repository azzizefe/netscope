// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect Telegraf / InfluxDB v2 Write API (TCP 8086).
pub fn dissect_telegraf_influxv2(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"POST /api/v2/write") {
        "InfluxDB v2 write request".to_string()
    } else {
        format!("InfluxDB v2 API ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TelegrafInfluxV2,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telegraf_influxv2_test() {
        let r = dissect_telegraf_influxv2(None, None, 40000, 8086, b"POST /api/v2/write HTTP/1.1\r\n");
        assert_eq!(r.protocol, Protocol::TelegrafInfluxV2);
        assert_eq!(r.summary, "InfluxDB v2 write request");
    }
}
