// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// NRPPa Procedure Codes (3GPP TS 38.455 §9.2).
fn nrppa_procedure_name(proc_code: u8) -> &'static str {
    match proc_code {
        0 => "E-CID Measurement Initiation",
        1 => "E-CID Measurement Failure",
        2 => "E-CID Measurement Report",
        3 => "OTDOA Information Exchange",
        4 => "Positioning Information Transfer",
        5 => "Measurement Information Transfer",
        6 => "TRP Information Exchange",
        _ => "NRPPa Procedure",
    }
}

/// Dissect an NR Positioning Protocol A (NRPPa — 3GPP TS 38.455) message over SCTP (PPID 66).
pub fn dissect_nrppa(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 3 {
        format!("NRPPa ({})", super::bytes(payload.len() as u64))
    } else {
        let pdu_type = payload[0];
        let proc_code = payload[1];
        let pdu_name = match pdu_type {
            0 => "Initiating Message",
            1 => "Successful Outcome",
            2 => "Unsuccessful Outcome",
            _ => "PDU",
        };
        let proc_name = nrppa_procedure_name(proc_code);

        format!("NRPPa {proc_name} — {pdu_name} (Proc {proc_code})")
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Nrppa,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nrppa_otdoa_exchange() {
        // PDU = 0 (Initiating Message), Proc = 3 (OTDOA Information Exchange)
        let payload = vec![0x00, 0x03, 0x00, 0x10];
        let res = dissect_nrppa(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Nrppa);
        assert!(res.summary.contains("OTDOA Information Exchange"));
    }

    #[test]
    fn test_nrppa_short_payload() {
        let payload = vec![0x00, 0x01];
        let res = dissect_nrppa(None, None, 0, 0, &payload);
        assert_eq!(res.protocol, Protocol::Nrppa);
        assert!(res.summary.contains("NRPPa (2 bytes)"));
    }
}
