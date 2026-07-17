// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a StatsD message (UDP 8125) — tiny fire-and-forget metric packets in
/// the form `name:value|type` (c counter, g gauge, ms timer, s set).
pub fn dissect_statsd(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let line = super::first_text_line(payload);
    let name: String = line.chars().take_while(|&c| c != ':').collect();
    let kind = line.rsplit('|').next().filter(|_| line.contains('|'));
    let summary = if name.is_empty() || !line.contains(':') {
        format!("StatsD ({} bytes)", payload.len())
    } else {
        let type_note = match kind {
            Some("c") => " (counter)",
            Some("g") => " (gauge)",
            Some("ms") => " (timer)",
            Some("s") => " (set)",
            _ => "",
        };
        format!("StatsD — {}{type_note}", super::truncate(&name, 40))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Statsd,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter() {
        let r = dissect_statsd(None, None, 40000, 8125, b"api.requests:1|c\n");
        assert_eq!(r.protocol, Protocol::Statsd);
        assert_eq!(r.summary, "StatsD — api.requests (counter)");
    }
}
