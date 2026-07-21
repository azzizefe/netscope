// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a SOME/IP message (UDP/TCP 30490+) — the service-oriented middleware
/// wiring together ECUs in AUTOSAR Adaptive vehicles. The header carries the
/// service and method ids and, at offset 14, the message type.
pub fn dissect_someip(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 16 {
        let service_id = u16::from_be_bytes([payload[0], payload[1]]);
        let method_id = u16::from_be_bytes([payload[2], payload[3]]);
        if service_id == 0xFFFF && method_id == 0x8100 {
            // Service discovery is where the interesting failures live — an
            // offer that never arrives, a subscription refused — so it gets its
            // own dissector rather than a flat label.
            return super::someip_sd::dissect_someip_sd(
                src_ip, dst_ip, src_port, dst_port, payload,
            );
        } else if payload[14] & super::someip_tp::TP_FLAG != 0 {
            // A segmented message has its own header after this one, and its
            // own failure mode: nothing retransmits a lost segment.
            return super::someip_tp::dissect_someip_tp(
                src_ip, dst_ip, src_port, dst_port, payload,
            );
        } else {
            let kind = match payload[14] {
                0x00 => "Request",
                0x01 => "Request (no return)",
                0x02 => "Notification",
                0x80 => "Response",
                0x81 => "Error",
                _ => "message",
            };
            format!("SOME/IP {kind} — service 0x{service_id:04x}")
        }
    } else {
        "SOME/IP (truncated)".to_string()
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SomeIp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request() {
        let mut p = Vec::new();
        p.extend_from_slice(&0x1234u16.to_be_bytes()); // service id
        p.extend_from_slice(&0x0001u16.to_be_bytes()); // method id
        p.extend_from_slice(&[0u8; 10]); // length, request id, versions
        p.push(0x00); // message type: Request
        p.push(0x00); // return code
        let r = dissect_someip(None, None, 40000, 30490, &p);
        assert_eq!(r.protocol, Protocol::SomeIp);
        assert_eq!(r.summary, "SOME/IP Request — service 0x1234");
    }
}
