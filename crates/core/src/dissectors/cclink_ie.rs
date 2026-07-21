// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use crate::models::Protocol;
use super::DissectedResult;

fn pdu_name(pdu_type: u8) -> &'static str {
    match pdu_type {
        0x15 => "TokenM",
        0x10 => "Persuasion",
        0x11 => "TestData",
        0x12 => "TestDataAck",
        0x13 => "Setup",
        0x14 => "SetupAck",
        0x20 => "MyStatus",
        0x40 => "Measure",
        0x41 => "MeasureAck",
        0x42 => "Offset",
        0x43 => "Update",
        0x82 => "CyclicDataRWw",
        0x83 => "CyclicDataRY",
        0x84 => "CyclicDataRWr",
        0x85 => "CyclicDataRX",
        0x22 => "Transient1",
        0x23 => "TransientAck",
        0x25 => "Transient2",
        0x28 => "ParamCheck",
        0x29 => "Parameter",
        0x1C => "Timer",
        0x26 => "IpTransient",
        0x00 => "Connect",
        0x01 => "ConnectAck",
        0x02 => "Scan",
        0x03 => "Collect",
        0x04 => "Select",
        0x05 => "Launch",
        0x06 => "Token",
        0x24 => "Dummy",
        0x2F => "NTNTest",
        0x80 => "CyclicDataW",
        0x81 => "CyclicDataB",
        0x8C => "CyclicDataOut1",
        0x8D => "CyclicDataOut2",
        0x8E => "CyclicDataIn1",
        0x8F => "CyclicDataIn2",
        0xC4 => "CyclicM",
        0xC5 => "CyclicS",
        0xC0 => "AcyclicPriority",
        0xC1 => "AcyclicDetection",
        0xC2 => "AcyclicDetectionAck",
        0xC3 => "AcyclicData",
        _ => "Unknown",
    }
}

/// Dissect a CC-Link IE frame on EtherType 0x890F.
pub fn dissect_cclink_ie(payload: &[u8]) -> DissectedResult {
    let base = DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::CcLinkIeControl,
        summary: String::new(),
    };

    let Some(&pdu_type) = payload.first() else {
        return DissectedResult {
            summary: "CC-Link IE (truncated)".into(),
            ..base
        };
    };

    let pdu = pdu_name(pdu_type);
    let summary = format!("CC-Link IE {} — {}", pdu, super::bytes(payload.len() as u64));

    DissectedResult {
        summary,
        ..base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cclink_ie_token_m() {
        let payload = vec![0x15, 0x00, 0x01, 0x02];
        let r = dissect_cclink_ie(&payload);
        assert_eq!(r.protocol, Protocol::CcLinkIeControl);
        assert_eq!(r.summary, "CC-Link IE TokenM — 4 bytes");
    }
}
