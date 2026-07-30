// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// INAP (Intelligent Network Application Part — ITU-T Q.1218 / 3GPP TS 29.078) operation codes.
fn inap_operation_name(opcode: u8) -> &'static str {
    match opcode {
        0x00 => "InitialDP",
        0x14 => "Connect",
        0x16 => "ReleaseCall",
        0x17 => "RequestReportBCSMEvent",
        0x18 => "EventReportBCSM",
        0x1F => "Continue",
        0x23 => "ApplyCharging",
        0x24 => "ApplyChargingReport",
        0x37 => "CallInformationRequest",
        0x38 => "CallInformationReport",
        _ => "INAP Operation",
    }
}

/// Dissect an INAP (Intelligent Network Application Part) PDU over TCAP/SS7.
pub fn dissect_inap(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.is_empty() {
        format!("INAP ({})", super::bytes(0u64))
    } else {
        let opcode = payload[0];
        let op_name = inap_operation_name(opcode);

        format!("INAP {op_name} (Opcode 0x{opcode:02X})")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Inap,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inap_initial_dp() {
        // Opcode = 0x00 (InitialDP)
        let payload = vec![0x00, 0x01, 0x02];
        let res = dissect_inap(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Inap);
        assert!(res.summary.contains("InitialDP"));
    }

    #[test]
    fn test_inap_empty_payload() {
        let payload = vec![];
        let res = dissect_inap(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Inap);
        assert!(res.summary.contains("INAP (0 bytes)"));
    }
}
