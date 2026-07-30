// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an SQL Server Browser message (UDP 1434) — the service that tells a
/// client which TCP port a named SQL Server instance is listening on. Its
/// replies enumerate instance names and versions, which also makes it a
/// favourite reconnaissance target.
pub fn dissect_mssqlbrowser(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match payload.first() {
        Some(0x02) => "SQL Browser — broadcast instance request".to_string(),
        Some(0x03) => "SQL Browser — named instance request".to_string(),
        Some(0x04) => "SQL Browser — dedicated admin port request".to_string(),
        Some(0x05) => {
            // Response: type, length(2), then a semicolon-delimited list.
            let text = String::from_utf8_lossy(&payload[3.min(payload.len())..]);
            let name = text
                .split(';')
                .nth(1)
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            if name.is_empty() {
                "SQL Browser — instance response".to_string()
            } else {
                format!("SQL Browser — instance {}", super::truncate(&name, 24))
            }
        }
        _ => format!("SQL Browser ({})", super::bytes(payload.len() as u64)),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::MssqlBrowser,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_names_the_instance() {
        let mut p = vec![0x05, 0x20, 0x00];
        p.extend_from_slice(b"ServerName;SQLPROD;InstanceName;SQLEXPRESS;");
        let r = dissect_mssqlbrowser(None, None, 1434, 40000, &p);
        assert_eq!(r.protocol, Protocol::MssqlBrowser);
        assert!(r.summary.contains("SQLPROD"), "{}", r.summary);
    }

    #[test]
    fn broadcast_request() {
        let r = dissect_mssqlbrowser(None, None, 40000, 1434, &[0x02]);
        assert!(r.summary.contains("broadcast"), "{}", r.summary);
    }
}
