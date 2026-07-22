// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect OpenTSDB Telnet / HTTP metric protocol (TCP 4242).
pub fn dissect_opentsdb(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"put ") {
        "OpenTSDB put metric".to_string()
    } else {
        format!("OpenTSDB metric stream ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::OpenTsdb,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opentsdb_put() {
        let r = dissect_opentsdb(None, None, 40000, 4242, b"put sys.cpu.user 1356998400 42.5 host=web01\n");
        assert_eq!(r.protocol, Protocol::OpenTsdb);
        assert_eq!(r.summary, "OpenTSDB put metric");
    }
}
