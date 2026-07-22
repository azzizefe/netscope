// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// X2AP Elementary Procedure codes (3GPP TS 36.423 §9.2).
fn x2ap_procedure_name(proc_code: u8) -> &'static str {
    match proc_code {
        0 => "Handover Request",
        1 => "Handover Cancel",
        2 => "Load Information",
        3 => "Error Indication",
        4 => "SN Status Transfer",
        5 => "UE Context Release",
        6 => "X2 Setup",
        7 => "Reset",
        8 => "gNB Status Indication",
        9 => "Resource Status Reporting",
        14 => "Cell Activation",
        15 => "Handover Report",
        _ => "X2AP Procedure",
    }
}

/// Dissect an LTE X2AP (X2 Application Protocol — 3GPP TS 36.423) message over SCTP (PPID 27).
pub fn dissect_x2ap(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 3 {
        format!("X2AP ({})", super::bytes(payload.len() as u64))
    } else {
        let pdu_type = payload[0];
        let proc_code = payload[1];
        let pdu_name = match pdu_type {
            0 => "Initiating Message",
            1 => "Successful Outcome",
            2 => "Unsuccessful Outcome",
            _ => "PDU",
        };
        let proc_name = x2ap_procedure_name(proc_code);

        format!("X2AP {proc_name} — {pdu_name} (Proc {proc_code})")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::X2ap,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x2ap_handover_request() {
        // PDU = 0 (Initiating Message), Proc = 0 (Handover Request)
        let payload = vec![0x00, 0x00, 0x00, 0x10];
        let res = dissect_x2ap(None, None, 36422, 36422, &payload);
        assert_eq!(res.protocol, Protocol::X2ap);
        assert!(res.summary.contains("Handover Request"));
        assert!(res.summary.contains("Initiating Message"));
    }

    #[test]
    fn test_x2ap_short_payload() {
        let payload = vec![0x00, 0x01];
        let res = dissect_x2ap(None, None, 36422, 36422, &payload);
        assert_eq!(res.protocol, Protocol::X2ap);
        assert!(res.summary.contains("X2AP (2 bytes)"));
    }
}
