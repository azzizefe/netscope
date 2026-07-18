// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Zabbix message (TCP 10051 server / 10050 agent) — monitoring data
/// between Zabbix agents and the server. Framed messages start with the "ZBXD"
/// header; agents may also send a bare metric key.
pub fn dissect_zabbix(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"ZBXD") {
        let flags = payload.get(4).copied().unwrap_or(0);
        if flags & 0x02 != 0 {
            "Zabbix protocol (compressed)".to_string()
        } else {
            "Zabbix protocol data".to_string()
        }
    } else {
        let line = super::first_text_line(payload);
        if line.is_empty() {
            format!("Zabbix ({} bytes)", payload.len())
        } else {
            format!("Zabbix — {}", super::truncate(&line, 40))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Zabbix,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framed() {
        let r = dissect_zabbix(None, None, 40000, 10051, b"ZBXD\x01\x10\x00\x00");
        assert_eq!(r.protocol, Protocol::Zabbix);
        assert_eq!(r.summary, "Zabbix protocol data");
    }
}
