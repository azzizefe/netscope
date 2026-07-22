// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// Dissect Zabbix Active Agent Protocol (TCP 10051).
pub fn dissect_zabbix_active(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"ZBXD\x01") {
        "Zabbix active agent header".to_string()
    } else {
        format!("Zabbix Active ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::ZabbixActive,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zabbix_active_test() {
        let r = dissect_zabbix_active(None, None, 40000, 10051, b"ZBXD\x01\x00\x00\x00");
        assert_eq!(r.protocol, Protocol::ZabbixActive);
        assert!(r.summary.contains("header"));
    }
}
