// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect Graphite Pickle Protocol (TCP 2004).
pub fn dissect_graphite_pickle(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 2 && (payload[0] == 0x80 || payload[1] == 0x80) {
        "Graphite Pickle stream".to_string()
    } else {
        format!("Graphite Pickle ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::GraphitePickle,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graphite_pickle_test() {
        let r = dissect_graphite_pickle(None, None, 40000, 2004, b"\x00\x00\x00\x08\x80\x02");
        assert_eq!(r.protocol, Protocol::GraphitePickle);
        assert!(r.summary.contains("Pickle"));
    }
}
