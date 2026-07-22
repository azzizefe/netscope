// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect ESPHome Native API (TCP 6053) frame.
pub fn dissect_esphome(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 3 && payload[0] == 0x00 {
        let msg_type = payload[2];
        let msg_name = match msg_type {
            1 => "Hello Request",
            2 => "Hello Response",
            3 => "Connect Request",
            4 => "Connect Response",
            5 => "Disconnect Request",
            6 => "Disconnect Response",
            7 => "Ping Request",
            8 => "Ping Response",
            9 => "DeviceInfo Request",
            10 => "DeviceInfo Response",
            11 => "ListEntities Request",
            12 => "ListEntities Done",
            13 => "SubscribeStates Request",
            14 => "StateResponse",
            _ => "Message",
        };
        format!("ESPHome Native API {msg_name} (type {msg_type})")
    } else {
        format!("ESPHome Native API ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Esphome,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_esphome_hello() {
        let payload = vec![0x00, 0x02, 0x01, 0x08, 0x01];
        let r = dissect_esphome(None, None, 40000, 6053, &payload);
        assert_eq!(r.protocol, Protocol::Esphome);
        assert_eq!(r.summary, "ESPHome Native API Hello Request (type 1)");
    }
}
