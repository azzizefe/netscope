// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect DoCAN (Diagnostic communication over CAN — ISO 15765-2 / ISO 14229-2 UDS).
pub fn dissect_docan(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.is_empty() {
        format!("DoCAN ({})", super::bytes(0u64))
    } else {
        let frame_type = (payload[0] >> 4) & 0x0F;
        let type_desc = match frame_type {
            0 => "Single Frame (SF)",
            1 => "First Frame (FF)",
            2 => "Consecutive Frame (CF)",
            3 => "Flow Control (FC)",
            _ => "Reserved Frame",
        };

        if frame_type == 0 && payload.len() >= 2 {
            let uds_sid = payload[1];
            let uds_desc = match uds_sid {
                0x10 => "DiagnosticSessionControl",
                0x11 => "ECUReset",
                0x22 => "ReadDataByIdentifier",
                0x27 => "SecurityAccess",
                0x2E => "WriteDataByIdentifier",
                0x31 => "RoutineControl",
                0x34 => "RequestDownload",
                0x36 => "TransferData",
                0x37 => "RequestTransferExit",
                0x50 => "DiagnosticSessionControl Response",
                0x62 => "ReadDataByIdentifier Response",
                0x67 => "SecurityAccess Response",
                0x7F => "Negative Response (NR)",
                _ => "UDS Service",
            };
            format!("DoCAN {type_desc} — UDS 0x{uds_sid:02X} ({uds_desc})")
        } else {
            format!("DoCAN {type_desc}")
        }
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::DoCan,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_docan_single_frame_uds() {
        // Single Frame (0x02 bytes len), UDS 0x10 (DiagnosticSessionControl)
        let payload = vec![0x02, 0x10, 0x01];
        let res = dissect_docan(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::DoCan);
        assert!(res.summary.contains("Single Frame (SF)"));
        assert!(res.summary.contains("DiagnosticSessionControl"));
    }

    #[test]
    fn test_docan_empty_payload() {
        let payload = vec![];
        let res = dissect_docan(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::DoCan);
        assert!(res.summary.contains("DoCAN (0 bytes)"));
    }
}
