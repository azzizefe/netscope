// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// O-RAN E2AP Procedure Codes (O-RAN WG3.E2GAP / TS 38.463).
fn e2ap_procedure_name(proc_code: u8) -> &'static str {
    match proc_code {
        1 => "E2 Setup",
        2 => "RIC Subscription",
        3 => "RIC Subscription Delete",
        4 => "RIC Indication",
        5 => "RIC Control",
        6 => "E2 Node Configuration Update",
        7 => "RIC Service Update",
        8 => "E2 Removal",
        _ => "E2AP Procedure",
    }
}

/// Dissect an O-RAN E2AP (Near-RT RIC E2 Application Protocol) message over SCTP (PPID 70).
pub fn dissect_e2ap(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 3 {
        format!("E2AP ({})", super::bytes(payload.len() as u64))
    } else {
        let pdu_type = payload[0];
        let proc_code = payload[1];
        let pdu_name = match pdu_type {
            0 => "Initiating Message",
            1 => "Successful Outcome",
            2 => "Unsuccessful Outcome",
            _ => "PDU",
        };
        let proc_name = e2ap_procedure_name(proc_code);

        format!("O-RAN E2AP {proc_name} — {pdu_name} (Proc {proc_code})")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::E2ap,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_e2ap_setup() {
        // PDU = 0 (Initiating Message), Proc = 1 (E2 Setup)
        let payload = vec![0x00, 0x01, 0x00, 0x10];
        let res = dissect_e2ap(None, None, 36421, 36421, &payload);
        assert_eq!(res.protocol, Protocol::E2ap);
        assert!(res.summary.contains("E2 Setup"));
        assert!(res.summary.contains("Initiating Message"));
    }

    #[test]
    fn test_e2ap_short_payload() {
        let payload = vec![0x00, 0x01];
        let res = dissect_e2ap(None, None, 36421, 36421, &payload);
        assert_eq!(res.protocol, Protocol::E2ap);
        assert!(res.summary.contains("E2AP (2 bytes)"));
    }
}
