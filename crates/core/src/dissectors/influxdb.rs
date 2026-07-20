// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an InfluxDB line-protocol message (UDP 8089) — the text format for
/// writing time-series points: `measurement,tags fields timestamp`. The
/// measurement name runs up to the first comma or space.
pub fn dissect_influxdb(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let line = super::first_text_line(payload);
    let measurement: String = line.chars().take_while(|&c| c != ',' && c != ' ').collect();
    let summary = if measurement.is_empty() {
        format!("InfluxDB ({})", super::bytes(payload.len() as u64))
    } else {
        format!("InfluxDB — {}", super::truncate(&measurement, 48))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Influxdb,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_point() {
        let r = dissect_influxdb(
            None,
            None,
            40000,
            8089,
            b"cpu,host=web1 usage=0.6 1700000000\n",
        );
        assert_eq!(r.protocol, Protocol::Influxdb);
        assert_eq!(r.summary, "InfluxDB — cpu");
    }
}
