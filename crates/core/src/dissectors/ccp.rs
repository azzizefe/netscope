// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// CCP Command and Response Opcodes (ASAM / CiA CAN Calibration Protocol v2.1).
fn ccp_opcode_name(cmd: u8) -> &'static str {
    match cmd {
        0x01 => "CONNECT",
        0x02 => "SET_MTA",
        0x03 => "DNLOAD",
        0x04 => "UPLOAD",
        0x05 => "BUILD_CHKSUM",
        0x06 => "UPLOAD_6 (Short Upload)",
        0x07 => "MOVE",
        0x08 => "SELECT_CAL_PAGE",
        0x09 => "GET_SEED",
        0x0A => "UNLOCK",
        0x0B => "GET_DAQ_SIZE",
        0x0C => "SET_DAQ_PTR",
        0x0D => "WRITE_DAQ",
        0x0E => "EXCHANGE_ID",
        0x0F => "PROGRAM",
        0x12 => "START_STOP",
        0x17 => "DISCONNECT",
        0xFF => "Command Return Message (CRM / ACK)",
        0xFE => "Event Message",
        _ => "Unknown Command",
    }
}

/// Dissect a CCP (CAN Calibration Protocol) packet.
pub fn dissect_ccp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.is_empty() {
        format!("CCP ({})", super::bytes(0u64))
    } else {
        let cmd = payload[0];
        let op_name = ccp_opcode_name(cmd);

        if cmd == 0xFF && payload.len() >= 2 {
            let return_code = payload[1];
            let status_str = match return_code {
                0x00 => "OK",
                0x01 => "DA_RUNNING",
                0x10 => "ERR_CMD_UNKNOWN",
                0x11 => "ERR_CMD_SYNTAX",
                0x12 => "ERR_PARAMETER_OUT_OF_RANGE",
                0x18 => "ERR_ACCESS_DENIED",
                _ => "ERR_OTHER",
            };
            format!("CCP Response — {status_str} (Code 0x{return_code:02X})")
        } else if payload.len() >= 2 {
            let ctr = payload[1];
            format!("CCP {op_name} (Command 0x{cmd:02X}) — CTR {ctr}")
        } else {
            format!("CCP {op_name} (Command 0x{cmd:02X})")
        }
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ccp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ccp_connect_command() {
        // Command = 0x01 (CONNECT), CTR = 5
        let payload = vec![0x01, 0x05, 0x00, 0x01];
        let res = dissect_ccp(None, None, 0, 5555, &payload);
        assert_eq!(res.protocol, Protocol::Ccp);
        assert!(res.summary.contains("CONNECT"));
        assert!(res.summary.contains("CTR 5"));
    }

    #[test]
    fn test_ccp_response_ok() {
        // CRM 0xFF, Return Code 0x00 (OK)
        let payload = vec![0xFF, 0x00, 0x05];
        let res = dissect_ccp(None, None, 0, 5555, &payload);
        assert_eq!(res.protocol, Protocol::Ccp);
        assert!(res.summary.contains("Response — OK"));
    }

    #[test]
    fn test_ccp_empty_payload() {
        let payload = vec![];
        let res = dissect_ccp(None, None, 0, 5555, &payload);
        assert_eq!(res.protocol, Protocol::Ccp);
        assert!(res.summary.contains("CCP (0 bytes)"));
    }
}
