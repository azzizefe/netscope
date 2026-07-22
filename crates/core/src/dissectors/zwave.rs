// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a Z-Wave / Z-IP Gateway message (UDP/TCP 41230).
pub fn dissect_zwave(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 2 {
        let cmd_class = payload[0];
        let class_name = match cmd_class {
            0x20 => "Basic",
            0x25 => "Binary Switch",
            0x26 => "Multilevel Switch",
            0x30 => "Binary Sensor",
            0x31 => "Multilevel Sensor",
            0x40 => "Thermostat Mode",
            0x62 => "Door Lock",
            0x70 => "Configuration",
            0x80 => "Battery",
            0x84 => "Wake Up",
            0x86 => "Version",
            _ => "Command",
        };
        format!("Z-Wave Command Class {class_name} (0x{cmd_class:02X})")
    } else {
        format!("Z-Wave ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Zwave,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zwave_binary_switch() {
        let payload = vec![0x25, 0x01, 0xFF];
        let r = dissect_zwave(None, None, 40000, 41230, &payload);
        assert_eq!(r.protocol, Protocol::Zwave);
        assert_eq!(r.summary, "Z-Wave Command Class Binary Switch (0x25)");
    }
}
