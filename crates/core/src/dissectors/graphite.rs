// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Graphite / Carbon plaintext metric (TCP 2003) — the line-oriented
/// format apps use to push time-series metrics: `metric.path value timestamp`.
pub fn dissect_graphite(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let line = super::first_text_line(payload);
    let metric = line.split_whitespace().next().unwrap_or("");
    let summary = if metric.is_empty() {
        format!("Graphite ({} bytes)", payload.len())
    } else {
        format!("Graphite — {}", super::truncate(metric, 48))
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Graphite,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_line() {
        let r = dissect_graphite(
            None,
            None,
            40000,
            2003,
            b"servers.web1.cpu 0.42 1700000000\n",
        );
        assert_eq!(r.protocol, Protocol::Graphite);
        assert_eq!(r.summary, "Graphite — servers.web1.cpu");
    }
}
