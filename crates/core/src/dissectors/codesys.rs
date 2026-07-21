// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! CODESYS V3 — the runtime and programming protocol for CODESYS-compatible
//! PLCs on TCP/UDP 11740.
//!
//! CODESYS is the most widely used IEC 61131-3 development environment.
//! A controller running the CODESYS runtime listens on TCP 11740 for
//! programming, monitoring and data exchange, and answers UDP broadcasts
//! on the same port for device discovery.
//!
//! The protocol uses a Service Group / Service ID header followed by a
//! little-endian length. The most common service group is the Block Driver
//! (0x01), which provides channel-based read/write/notify operations.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Recognised service groups in the CODESYS Network Protocol.
fn service_group_name(sg: u8) -> Option<&'static str> {
    Some(match sg {
        0x01 => "Block Driver",
        0x02 => "Service",
        0x03 => "Logger",
        _ => return None,
    })
}

/// Block Driver (service group 0x01) service IDs.
fn block_driver_name(sid: u8) -> Option<&'static str> {
    Some(match sid {
        0x01 => "Open Channel",
        0x02 => "Close Channel",
        0x03 => "Ping",
        0x04 => "Read",
        0x05 => "Write",
        0x06 => "Read/Write",
        0x07 => "Notify",
        0x08 => "Blob",
        0x09 => "Close",
        _ => return None,
    })
}

/// Check whether the payload looks like a CODESYS V3 Network Protocol frame.
///
/// The header is: ServiceGroup (1) + ServiceID (1) + Length (4, LE). The
/// length must be self-consistent with the remaining payload.
pub(crate) fn looks_like_codesys(payload: &[u8]) -> bool {
    if payload.len() < 6 {
        return false;
    }
    let sg = payload[0];
    // Service groups above 0x0F are unknown — a random byte in the ephemeral
    // range would be above this.
    if sg == 0 || sg > 0x0F {
        return false;
    }
    let declared = u32::from_le_bytes([payload[2], payload[3], payload[4], payload[5]]) as usize;
    // The declared length covers the remaining payload after the 6-byte header,
    // but gateways sometimes fragment or pad — allow a little slack.
    let remaining = payload.len().saturating_sub(6);
    if declared > remaining + 64 {
        return false;
    }
    true
}

/// Dissect a CODESYS V3 frame from TCP port 11740.
pub fn dissect_codesys(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Codesys,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    if payload.len() < 6 {
        return format!("CODESYS ({})", super::bytes(payload.len() as u64));
    }

    let sg = payload[0];
    let sid = payload[1];
    let declared =
        u32::from_le_bytes([payload[2], payload[3], payload[4], payload[5]]);

    let group = service_group_name(sg).unwrap_or("message");

    // For the Block Driver, name the specific operation.
    if sg == 0x01 {
        if let Some(op) = block_driver_name(sid) {
            return format!("CODESYS {group} — {op} ({})", super::bytes(declared as u64));
        }
        return format!("CODESYS {group} — service {sid:#04x} ({})", super::bytes(declared as u64));
    }

    format!("CODESYS {group} — service {sid:#04x} ({})", super::bytes(declared as u64))
}

/// Dissect a CODESYS discovery broadcast from UDP port 11740.
///
/// These are sent by engineering tools to find controllers on the network.
/// The payload is typically ASCII-printable with device metadata.
pub fn dissect_codesys_discovery(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.is_empty() {
        "CODESYS discovery".to_string()
    } else {
        // Discovery payloads are mostly ASCII text with occasional null bytes
        // as separators between fields (device name, version, etc.).
        let printable: Vec<u8> = payload
            .iter()
            .copied()
            .map(|b| if b.is_ascii_graphic() || b == b' ' { b } else { b' ' })
            .collect();
        let text = String::from_utf8_lossy(&printable);
        let mut snippet: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
        snippet.truncate(48);
        if snippet.len() < text.trim().len().min(48) {
            format!("CODESYS discovery — \"{snippet}…\"")
        } else {
            format!("CODESYS discovery — \"{snippet}\"")
        }
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Codesys,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a CODESYS frame: ServiceGroup, ServiceID, then length + payload.
    fn frame(sg: u8, sid: u8, body: &[u8]) -> Vec<u8> {
        let len = body.len() as u32;
        let mut p = vec![sg, sid];
        p.extend_from_slice(&len.to_le_bytes());
        p.extend_from_slice(body);
        p
    }

    #[test]
    fn block_driver_read() {
        let p = frame(0x01, 0x04, &[0xAA; 16]);
        let r = dissect_codesys(None, None, 40000, 11740, &p);
        assert_eq!(r.protocol, Protocol::Codesys);
        assert!(
            r.summary.contains("CODESYS Block Driver — Read"),
            "{}",
            r.summary
        );
    }

    #[test]
    fn block_driver_write() {
        let p = frame(0x01, 0x05, &[0xBB; 32]);
        let r = dissect_codesys(None, None, 40000, 11740, &p);
        assert!(r.summary.contains("Write"), "{}", r.summary);
    }

    #[test]
    fn non_block_driver_service() {
        let p = frame(0x03, 0x01, &[0x00; 8]);
        let r = dissect_codesys(None, None, 40000, 11740, &p);
        assert!(r.summary.contains("CODESYS Logger"), "{}", r.summary);
    }

    #[test]
    fn unrecognised_service() {
        let p = frame(0x0F, 0xFF, &[0x00; 4]);
        let r = dissect_codesys(None, None, 40000, 11740, &p);
        assert!(r.summary.contains("CODESYS"), "{}", r.summary);
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_codesys(None, None, 40000, 11740, &[0x01, 0x04, 0x10]);
        assert!(r.summary.starts_with("CODESYS"));
        assert!(
            dissect_codesys(None, None, 1, 11740, &[]).summary.starts_with("CODESYS")
        );
    }

    #[test]
    fn invalid_service_group_is_rejected() {
        // Service group 0x20 is outside the valid range.
        assert!(!looks_like_codesys(&frame(0x20, 0x01, &[0; 4])));
        // Service group 0x00 is invalid.
        assert!(!looks_like_codesys(&frame(0x00, 0x01, &[0; 4])));
    }

    #[test]
    fn length_mismatch_is_rejected() {
        // Declare 200 bytes but provide only 4.
        let p = frame(0x01, 0x04, &[0x00; 4]);
        let mut p = p;
        p[3] = 200; // patch the length to be impossibly large
        assert!(!looks_like_codesys(&p));
    }

    #[test]
    fn normal_traffic_does_not_false_trigger() {
        assert!(!looks_like_codesys(b"GET / HTTP/1.1\r\n\r\n"));
        assert!(!looks_like_codesys(b"\x16\x03\x01\x00\x00\x00"));
        assert!(!looks_like_codesys(&[]));
    }

    #[test]
    fn discovery_text_payload() {
        let r = dissect_codesys_discovery(
            None,
            None,
            40000,
            11740,
            b"CODESYS V3.5 SP20 Patch 3\x00PLC_001",
        );
        assert_eq!(r.protocol, Protocol::Codesys);
        assert!(r.summary.contains("CODESYS discovery"), "{}", r.summary);
        assert!(r.summary.contains("CODESYS V3.5"), "{}", r.summary);
    }

    #[test]
    fn discovery_empty() {
        let r = dissect_codesys_discovery(None, None, 40000, 11740, &[]);
        assert_eq!(r.summary, "CODESYS discovery");
    }
}
