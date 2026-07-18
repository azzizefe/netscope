// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a WS-Discovery message (UDP 3702) — the SOAP/XML discovery used by
/// Windows network devices and ONVIF IP cameras. The SOAP action names the
/// operation (Probe / Hello / Bye / Resolve).
pub fn dissect_wsd(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let text = String::from_utf8_lossy(&payload[..payload.len().min(2048)]);
    let action = if text.contains("Probe") {
        "Probe (searching)"
    } else if text.contains("ProbeMatches") {
        "ProbeMatches"
    } else if text.contains("Hello") {
        "Hello (joining)"
    } else if text.contains("Bye") {
        "Bye (leaving)"
    } else if text.contains("Resolve") {
        "Resolve"
    } else {
        "message"
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::WsDiscovery,
        summary: format!("WS-Discovery {action}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe() {
        let body = br#"<soap:Envelope><wsd:Probe/></soap:Envelope>"#;
        let r = dissect_wsd(None, None, 40000, 3702, body);
        assert_eq!(r.protocol, Protocol::WsDiscovery);
        assert!(r.summary.contains("Probe"), "{}", r.summary);
    }
}
