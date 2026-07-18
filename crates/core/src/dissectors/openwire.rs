// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an OpenWire message (TCP 61616) — the native protocol of Apache
/// ActiveMQ. Each frame is a 4-byte length followed by a data-type byte; the
/// opening WireFormatInfo carries the "ActiveMQ" magic.
pub fn dissect_openwire(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let head = &payload[..payload.len().min(64)];
    let summary = if memchr::memmem::find(head, b"ActiveMQ").is_some() {
        "OpenWire WireFormatInfo (handshake)".to_string()
    } else {
        match payload.get(4) {
            Some(2) => "OpenWire BrokerInfo".to_string(),
            Some(3) => "OpenWire ConnectionInfo".to_string(),
            Some(4) => "OpenWire SessionInfo".to_string(),
            Some(5) => "OpenWire ConsumerInfo".to_string(),
            Some(6) => "OpenWire ProducerInfo".to_string(),
            Some(21) => "OpenWire MessageDispatch".to_string(),
            Some(23) => "OpenWire ActiveMQMessage".to_string(),
            _ => format!("OpenWire frame ({} bytes)", payload.len()),
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Openwire,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wireformat_handshake() {
        let mut p = 30u32.to_be_bytes().to_vec();
        p.extend_from_slice(b"\x01\x00\x08ActiveMQ");
        let r = dissect_openwire(None, None, 40000, 61616, &p);
        assert_eq!(r.protocol, Protocol::Openwire);
        assert!(r.summary.contains("WireFormatInfo"), "{}", r.summary);
    }

    #[test]
    fn broker_info() {
        let mut p = 12u32.to_be_bytes().to_vec();
        p.push(2); // data type: BrokerInfo
        p.extend_from_slice(&[0u8; 7]);
        let r = dissect_openwire(None, None, 40000, 61616, &p);
        assert_eq!(r.summary, "OpenWire BrokerInfo");
    }
}
