// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect Zigbee Green Power (ZGP / GPDF Green Power Data Frame) 802.15.4 frame.
pub fn dissect_zigbee_gp(payload: &[u8]) -> DissectedResult {
    let summary = if payload.len() >= 2 {
        let frame_ctrl = payload[0];
        let app_id = frame_ctrl & 0x07;
        let cmd_id = payload.get(1).copied().unwrap_or(0);
        let cmd_name = match cmd_id {
            0x20 => "Button Press",
            0x21 => "Button Release",
            0x22 => "Toggle",
            0x30 => "Commissioning",
            0xE0 => "Attribute Report",
            0xE3 => "Multi-Cluster Report",
            _ => "Command",
        };
        format!("Zigbee Green Power GPDF {cmd_name} (0x{cmd_id:02X}, AppID {app_id})")
    } else {
        format!("Zigbee Green Power ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::ZigbeeGreenPower,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zigbee_gp_toggle() {
        let payload = vec![0x00, 0x22];
        let r = dissect_zigbee_gp(&payload);
        assert_eq!(r.protocol, Protocol::ZigbeeGreenPower);
        assert_eq!(r.summary, "Zigbee Green Power GPDF Toggle (0x22, AppID 0)");
    }
}
