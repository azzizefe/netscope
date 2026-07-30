// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an MQTT-SN message (UDP 1883) — the sensor-network variant of MQTT
/// for constrained/UDP devices. A length of 0x01 means a 3-byte length prefix,
/// so the message type sits at offset 3 rather than 1.
pub fn dissect_mqttsn(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let type_idx = if payload.first() == Some(&0x01) { 3 } else { 1 };
    let summary = match payload.get(type_idx) {
        Some(&t) => {
            let name = match t {
                0x00 => "ADVERTISE",
                0x01 => "SEARCHGW",
                0x02 => "GWINFO",
                0x04 => "CONNECT",
                0x05 => "CONNACK",
                0x0C => "PUBLISH",
                0x12 => "SUBSCRIBE",
                0x13 => "SUBACK",
                0x16 => "PINGREQ",
                0x17 => "PINGRESP",
                0x18 => "DISCONNECT",
                _ => "message",
            };
            format!("MQTT-SN {name}")
        }
        None => "MQTT-SN (truncated)".to_string(),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::MqttSn,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish() {
        // length 7, type 0x0C (PUBLISH).
        let r = dissect_mqttsn(None, None, 40000, 1883, &[0x07, 0x0C, 0x00, 0x00]);
        assert_eq!(r.protocol, Protocol::MqttSn);
        assert_eq!(r.summary, "MQTT-SN PUBLISH");
    }
}
