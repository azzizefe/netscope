// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;
use super::{modbus, DissectedResult};

/// Whether a payload is a Modbus ASCII frame.
///
/// It must start with ':', end with '\r\n', contain only valid hex characters,
/// and have a valid LRC checksum.
pub(crate) fn looks_like_modbus_ascii(payload: &[u8]) -> bool {
    if payload.len() < 9 {
        return false;
    }
    if payload[0] != b':'
        || payload[payload.len() - 2] != b'\r'
        || payload[payload.len() - 1] != b'\n'
    {
        return false;
    }
    let hex_part = &payload[1..payload.len() - 2];
    if hex_part.len() % 2 != 0 {
        return false;
    }
    let mut bytes = Vec::with_capacity(hex_part.len() / 2);
    for chunk in hex_part.chunks_exact(2) {
        let Ok(s) = std::str::from_utf8(chunk) else {
            return false;
        };
        let Ok(b) = u8::from_str_radix(s, 16) else {
            return false;
        };
        bytes.push(b);
    }
    if bytes.is_empty() {
        return false;
    }
    let (body, lrc_val) = bytes.split_at(bytes.len() - 1);
    let mut sum: u8 = 0;
    for &b in body {
        sum = sum.wrapping_add(b);
    }
    let expected_lrc = 0u8.wrapping_sub(sum);
    lrc_val[0] == expected_lrc
}

/// Dissect a Modbus ASCII frame.
pub fn dissect_modbus_ascii(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let base = DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::ModbusAscii,
        summary: String::new(),
    };

    let hex_part = &payload[1..payload.len() - 2];
    let mut bytes = Vec::with_capacity(hex_part.len() / 2);
    for chunk in hex_part.chunks_exact(2) {
        let Ok(s) = std::str::from_utf8(chunk) else {
            continue;
        };
        let Ok(b) = u8::from_str_radix(s, 16) else {
            continue;
        };
        bytes.push(b);
    }

    if bytes.len() < 2 {
        return DissectedResult {
            summary: "Modbus ASCII (truncated)".into(),
            ..base
        };
    }

    let address = bytes[0];
    let function = bytes[1];

    let who = if address == 0 {
        "broadcast".to_string()
    } else {
        format!("unit {address}")
    };

    let summary = if function & 0x80 != 0 {
        let asked = function & 0x7F;
        let reason = bytes
            .get(2)
            .map(|&e| modbus::exception_name(e))
            .unwrap_or("unknown exception");
        format!(
            "Modbus ASCII {who} — {} refused: {reason}",
            modbus::function_name(asked)
        )
    } else {
        format!(
            "Modbus ASCII {who} — {}",
            modbus::function_name(function)
        )
    };

    DissectedResult { summary, ..base }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_modbus_ascii_request() {
        // unit 1, function 3 (Read), start 0, count 2, LRC = 256 - (1+3+0+0+0+2) = 250 (0xFA)
        // colon + "010300000002FA" + "\r\n"
        let payload = b":010300000002FA\r\n";
        assert!(looks_like_modbus_ascii(payload));
        let r = dissect_modbus_ascii(None, None, 502, 502, payload);
        assert_eq!(r.protocol, Protocol::ModbusAscii);
        assert_eq!(
            r.summary,
            "Modbus ASCII unit 1 — Read Holding Registers"
        );
    }
}
