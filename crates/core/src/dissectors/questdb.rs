// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect QuestDB InfluxDB Line Protocol (ILP) TCP/UDP ingestion (TCP/UDP 9009).
pub fn dissect_questdb(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.contains(&b'=') && payload.contains(&b'\n') {
        "QuestDB ILP ingestion line".to_string()
    } else {
        format!("QuestDB ILP stream ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::QuestDb,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn questdb_ilp() {
        let r = dissect_questdb(None, None, 40000, 9009, b"trades,symbol=BTC-USD price=30000 1600000000000\n");
        assert_eq!(r.protocol, Protocol::QuestDb);
        assert_eq!(r.summary, "QuestDB ILP ingestion line");
    }
}
