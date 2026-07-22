// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// XwAP Procedure Codes (3GPP TS 36.463 §9.2).
fn xwap_procedure_name(proc_code: u8) -> &'static str {
    match proc_code {
        0 => "Xw Setup",
        1 => "WT Association Request",
        2 => "WT Configuration Update",
        3 => "eNB Configuration Update",
        4 => "WLAN Status Reporting",
        5 => "Error Indication",
        6 => "Reset",
        _ => "XwAP Procedure",
    }
}

/// Dissect an XwAP (LTE-WLAN Aggregation Application Protocol — 3GPP TS 36.463) message over SCTP (PPID 59).
pub fn dissect_xwap(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 3 {
        format!("XwAP ({})", super::bytes(payload.len() as u64))
    } else {
        let pdu_type = payload[0];
        let proc_code = payload[1];
        let pdu_name = match pdu_type {
            0 => "Initiating Message",
            1 => "Successful Outcome",
            2 => "Unsuccessful Outcome",
            _ => "PDU",
        };
        let proc_name = xwap_procedure_name(proc_code);

        format!("XwAP {proc_name} — {pdu_name} (Proc {proc_code})")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Xwap,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xwap_setup() {
        // PDU = 0 (Initiating Message), Proc = 0 (Xw Setup)
        let payload = vec![0x00, 0x00, 0x00, 0x10];
        let res = dissect_xwap(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Xwap);
        assert!(res.summary.contains("Xw Setup"));
    }

    #[test]
    fn test_xwap_short_payload() {
        let payload = vec![0x00, 0x01];
        let res = dissect_xwap(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Xwap);
        assert!(res.summary.contains("XwAP (2 bytes)"));
    }
}
