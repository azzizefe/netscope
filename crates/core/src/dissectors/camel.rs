// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// CAMEL / CAP Operation codes (3GPP TS 29.078 §6.1).
fn camel_operation_name(opcode: u8) -> &'static str {
    match opcode {
        0x00 => "InitialDP",
        0x14 => "Connect",
        0x16 => "ReleaseCall",
        0x17 => "RequestReportBCSMEvent",
        0x18 => "EventReportBCSM",
        0x1F => "Continue",
        0x22 => "FurnishChargingInformation",
        0x23 => "ApplyCharging",
        0x24 => "ApplyChargingReport",
        0x3C => "InitialDPSMS",
        0x3E => "ConnectSMS",
        0x40 => "EventReportSMS",
        _ => "CAMEL Operation",
    }
}

/// Dissect a CAMEL / CAP (Customised Applications for Mobile network Enhanced Logic) message over TCAP/SS7.
pub fn dissect_camel(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.is_empty() {
        format!("CAMEL ({})", super::bytes(0u64))
    } else {
        let opcode = payload[0];
        let op_name = camel_operation_name(opcode);

        format!("CAMEL/CAP {op_name} (Opcode 0x{opcode:02X})")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Camel,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_camel_initial_dp_sms() {
        // Opcode = 0x3C (InitialDPSMS)
        let payload = vec![0x3C, 0x01, 0x02];
        let res = dissect_camel(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Camel);
        assert!(res.summary.contains("InitialDPSMS"));
    }

    #[test]
    fn test_camel_empty_payload() {
        let payload = vec![];
        let res = dissect_camel(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Camel);
        assert!(res.summary.contains("CAMEL (0 bytes)"));
    }
}
