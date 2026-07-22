// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// O-RAN E1AP Procedure Codes (3GPP TS 38.463 / O-RAN E1 Interface).
fn oran_e1_procedure_name(proc_code: u8) -> &'static str {
    match proc_code {
        0 => "Reset",
        1 => "Error Indication",
        2 => "GNB-CU-UP E1 Setup",
        3 => "GNB-CU-CP E1 Setup",
        4 => "GNB-CU-UP Configuration Update",
        5 => "GNB-CU-CP Configuration Update",
        6 => "E1 Release",
        7 => "Bearer Context Setup",
        8 => "Bearer Context Modification",
        9 => "Bearer Context Release",
        10 => "Bearer Context Inactivity Notification",
        _ => "O-RAN E1 Procedure",
    }
}

/// Dissect an O-RAN E1AP / M-Plane interface message (3GPP TS 38.463 / O-RAN WG1).
pub fn dissect_oran_e1(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 3 {
        format!("O-RAN E1/M-Plane ({})", super::bytes(payload.len() as u64))
    } else {
        let pdu_type = payload[0];
        let proc_code = payload[1];
        let pdu_name = match pdu_type {
            0 => "Initiating Message",
            1 => "Successful Outcome",
            2 => "Unsuccessful Outcome",
            _ => "PDU",
        };
        let proc_name = oran_e1_procedure_name(proc_code);

        format!("O-RAN E1 {proc_name} — {pdu_name} (Proc {proc_code})")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::OranE1,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oran_e1_bearer_context_setup() {
        // PDU = 0 (Initiating Message), Proc = 7 (Bearer Context Setup)
        let payload = vec![0x00, 0x07, 0x00, 0x10];
        let res = dissect_oran_e1(None, None, 38463, 38463, &payload);
        assert_eq!(res.protocol, Protocol::OranE1);
        assert!(res.summary.contains("Bearer Context Setup"));
    }

    #[test]
    fn test_oran_e1_short_payload() {
        let payload = vec![0x00, 0x01];
        let res = dissect_oran_e1(None, None, 38463, 38463, &payload);
        assert_eq!(res.protocol, Protocol::OranE1);
        assert!(res.summary.contains("O-RAN E1/M-Plane (2 bytes)"));
    }
}
