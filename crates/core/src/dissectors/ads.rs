// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// ADS command ids (Beckhoff ADS specification).
fn command_name(cmd: u16) -> Option<&'static str> {
    Some(match cmd {
        0x0000 => "Invalid",
        0x0001 => "Read Device Info",
        0x0002 => "Read",
        0x0003 => "Write",
        0x0004 => "Read State",
        0x0005 => "Write Control",
        0x0006 => "Add Device Notification",
        0x0007 => "Delete Device Notification",
        0x0008 => "Device Notification",
        0x0009 => "Read Write",
        _ => return None,
    })
}

/// ADS state flags: bit 0 distinguishes a request from a response.
const STATE_RESPONSE: u16 = 0x0001;

/// The AMS/TCP header is six bytes (two reserved, four length) before the AMS
/// header proper begins.
const AMS_TCP_HEADER: usize = 6;
/// The AMS header: target NetId (6) + port (2), source NetId (6) + port (2),
/// command id (2), state flags (2), data length (4), error code (4), invoke id (4).
const AMS_HEADER: usize = 32;

/// Format an AMS NetId, which is six bytes written like an IPv4 address with
/// two extra octets — `192.168.1.10.1.1`.
fn net_id(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| b.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

/// Dissect an ADS message — Beckhoff TwinCAT's automation protocol, on TCP
/// 48898 (Beckhoff ADS specification).
///
/// Devices are addressed by an AMS NetId rather than by IP, so the NetId is
/// what actually identifies which controller is being talked to.
pub fn dissect_ads(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary =
        parse(payload).unwrap_or_else(|| format!("ADS ({})", super::bytes(payload.len() as u64)));
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ads,
        summary,
    }
}

fn parse(payload: &[u8]) -> Option<String> {
    if payload.len() < AMS_TCP_HEADER + AMS_HEADER {
        return None;
    }
    // The first two bytes of the AMS/TCP header are reserved and must be zero;
    // checking them keeps unrelated traffic on this port from being decoded.
    if payload[0] != 0 || payload[1] != 0 {
        return None;
    }
    let ams = &payload[AMS_TCP_HEADER..];
    let target = net_id(&ams[0..6]);
    let target_port = u16::from_le_bytes([ams[6], ams[7]]);
    let command = u16::from_le_bytes([ams[16], ams[17]]);
    let state = u16::from_le_bytes([ams[18], ams[19]]);
    let error = u32::from_le_bytes([ams[24], ams[25], ams[26], ams[27]]);

    let direction = if state & STATE_RESPONSE != 0 {
        "response"
    } else {
        "request"
    };
    let name = match command_name(command) {
        Some(n) => n.to_string(),
        None => format!("command 0x{command:04x}"),
    };
    Some(if error != 0 {
        format!("ADS {name} ({direction}) — {target}:{target_port}, error 0x{error:08x}")
    } else {
        format!("ADS {name} ({direction}) — {target}:{target_port}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an AMS/TCP frame carrying one ADS command.
    fn ads(command: u16, response: bool, error: u32) -> Vec<u8> {
        let mut p = vec![0x00, 0x00]; // reserved
        p.extend_from_slice(&0u32.to_le_bytes()); // length, unused here
        p.extend_from_slice(&[192, 168, 1, 10, 1, 1]); // target NetId
        p.extend_from_slice(&851u16.to_le_bytes()); // target port
        p.extend_from_slice(&[192, 168, 1, 20, 1, 1]); // source NetId
        p.extend_from_slice(&32905u16.to_le_bytes()); // source port
        p.extend_from_slice(&command.to_le_bytes());
        p.extend_from_slice(&(if response { 1u16 } else { 4u16 }).to_le_bytes());
        p.extend_from_slice(&0u32.to_le_bytes()); // data length
        p.extend_from_slice(&error.to_le_bytes());
        p.extend_from_slice(&1u32.to_le_bytes()); // invoke id
        p
    }

    #[test]
    fn read_request_names_the_target() {
        let r = dissect_ads(None, None, 40000, 48898, &ads(0x0002, false, 0));
        assert_eq!(r.protocol, Protocol::Ads);
        assert_eq!(r.summary, "ADS Read (request) — 192.168.1.10.1.1:851");
    }

    #[test]
    fn write_control_changes_plc_state() {
        let r = dissect_ads(None, None, 40000, 48898, &ads(0x0005, false, 0));
        assert_eq!(
            r.summary,
            "ADS Write Control (request) — 192.168.1.10.1.1:851"
        );
    }

    /// The state flags carry the request/response bit; the error code is a
    /// separate field and is only worth showing when it is non-zero.
    #[test]
    fn response_with_an_error_reports_both() {
        let r = dissect_ads(None, None, 48898, 40000, &ads(0x0002, true, 0x0705));
        assert_eq!(
            r.summary,
            "ADS Read (response) — 192.168.1.10.1.1:851, error 0x00000705"
        );
    }

    #[test]
    fn unknown_command_reports_its_id() {
        let r = dissect_ads(None, None, 1, 48898, &ads(0x00FF, false, 0));
        assert_eq!(
            r.summary,
            "ADS command 0x00ff (request) — 192.168.1.10.1.1:851"
        );
    }

    /// The reserved bytes guard against decoding unrelated traffic that happens
    /// to land on this port.
    #[test]
    fn non_zero_reserved_bytes_are_not_claimed() {
        let mut p = ads(0x0002, false, 0);
        p[0] = 0x47; // 'G', as an HTTP request would start
        let r = dissect_ads(None, None, 1, 48898, &p);
        assert_eq!(r.summary, format!("ADS ({} bytes)", p.len()));
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_ads(None, None, 1, 48898, &[0x00, 0x00, 0x01]);
        assert_eq!(r.summary, "ADS (3 bytes)");
    }
}
