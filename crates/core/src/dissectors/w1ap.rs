// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// W1AP Procedure Codes (3GPP TS 37.473 §9.2).
fn w1ap_procedure_name(proc_code: u8) -> &'static str {
    match proc_code {
        0 => "W1 Setup",
        1 => "gNB-DU Configuration Update",
        2 => "gNB-CU Configuration Update",
        3 => "UE Context Setup",
        4 => "UE Context Release",
        5 => "UE Context Modification",
        6 => "Error Indication",
        7 => "Reset",
        _ => "W1AP Procedure",
    }
}

/// Dissect a W1AP (3GPP TS 37.473 ng-eNB-CU to ng-eNB-DU) message over SCTP (PPID 63).
pub fn dissect_w1ap(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 3 {
        format!("W1AP ({})", super::bytes(payload.len() as u64))
    } else {
        let pdu_type = payload[0];
        let proc_code = payload[1];
        let pdu_name = match pdu_type {
            0 => "Initiating Message",
            1 => "Successful Outcome",
            2 => "Unsuccessful Outcome",
            _ => "PDU",
        };
        let proc_name = w1ap_procedure_name(proc_code);

        format!("W1AP {proc_name} — {pdu_name} (Proc {proc_code})")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::W1ap,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_w1ap_setup() {
        // PDU = 0 (Initiating Message), Proc = 0 (W1 Setup)
        let payload = vec![0x00, 0x00, 0x00, 0x10];
        let res = dissect_w1ap(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::W1ap);
        assert!(res.summary.contains("W1 Setup"));
    }

    #[test]
    fn test_w1ap_short_payload() {
        let payload = vec![0x00, 0x01];
        let res = dissect_w1ap(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::W1ap);
        assert!(res.summary.contains("W1AP (2 bytes)"));
    }
}
