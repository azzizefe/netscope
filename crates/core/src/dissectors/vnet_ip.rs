// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Yokogawa Vnet/IP message type descriptions.
fn message_type(msg_type: u8) -> &'static str {
    match msg_type {
        0x01 => "Cyclic Process Data",
        0x02 => "Transient Command Request",
        0x03 => "Transient Command Reply",
        0x04 => "Time Synchronization",
        0x05 => "Alarm / Event",
        0x06 => "Network Heartbeat",
        _ => "Control Message",
    }
}

/// Dissect a Yokogawa Vnet/IP DCS real-time control frame on UDP ports 13000..=13002.
pub fn dissect_vnet_ip(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 3 {
        format!("Vnet/IP ({})", super::bytes(payload.len() as u64))
    } else {
        let domain = payload[0];
        let station = payload[1];
        let msg = payload[2];
        let mname = message_type(msg);

        format!("Vnet/IP {mname} — domain {domain}, station {station}")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::VnetIp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vnet_ip_cyclic() {
        // Domain: 1, Station: 5, Msg: 0x01 (Cyclic Process Data)
        let payload = vec![0x01, 0x05, 0x01, 0x00, 0x00];
        let res = dissect_vnet_ip(None, None, 40000, 13000, &payload);
        assert_eq!(res.protocol, Protocol::VnetIp);
        assert!(res.summary.contains("Cyclic Process Data"));
        assert!(res.summary.contains("domain 1, station 5"));
    }

    #[test]
    fn test_vnet_ip_short_payload() {
        let payload = vec![0x01, 0x05];
        let res = dissect_vnet_ip(None, None, 40000, 13000, &payload);
        assert_eq!(res.protocol, Protocol::VnetIp);
        assert!(res.summary.contains("Vnet/IP (2 bytes)"));
    }
}
