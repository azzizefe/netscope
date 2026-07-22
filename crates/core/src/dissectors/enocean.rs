// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an EnOcean Serial Protocol 3 (ESP3 / EnOcean over IP) frame (`0x55` sync header).
pub fn dissect_enocean(payload: &[u8]) -> DissectedResult {
    let summary = if payload.len() >= 6 && payload[0] == 0x55 {
        let pkt_type = payload[4];
        let type_name = match pkt_type {
            0x01 => "RADIO_ERP1",
            0x02 => "RESPONSE",
            0x03 => "RADIO_SUB_TEL",
            0x04 => "EVENT",
            0x05 => "COMMON_COMMAND",
            0x06 => "SMART_ACK_COMMAND",
            0x0A => "RADIO_ERP2",
            _ => "Packet",
        };
        format!("EnOcean ESP3 {type_name}")
    } else {
        format!("EnOcean ({})", super::bytes(payload.len() as u64))
    };

    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Enocean,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enocean_radio_erp1() {
        let payload = vec![0x55, 0x00, 0x07, 0x07, 0x01, 0x7A];
        let r = dissect_enocean(&payload);
        assert_eq!(r.protocol, Protocol::Enocean);
        assert_eq!(r.summary, "EnOcean ESP3 RADIO_ERP1");
    }
}
