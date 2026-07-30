// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{ngap_common, DissectedResult};

/// SABP procedure codes (3GPP TS 25.419).
fn procedure(code: u8) -> Option<&'static str> {
    Some(match code {
        0 => "Write-Replace",
        1 => "Kill",
        2 => "Load-Status-Enquiry",
        3 => "Message-Status-Query",
        4 => "Reset",
        5 => "Restart-Indication",
        6 => "Failure-Indication",
        7 => "Error-Indication",
        _ => return None,
    })
}

/// Dissect a SABP message — is the 3G equivalent of SBc-AP — cell broadcast to UMTS cells, carried over
/// SCTP with payload protocol identifier 31 (3GPP TS 25.419).
pub fn dissect_sabp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Sabp,
        summary: ngap_common::summarize("SABP", payload, procedure),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissectors::ngap_common::test_helpers::ap_pdu;
    use crate::dissectors::ngap_common::MessageKind;

    #[test]
    fn first_procedure_is_named() {
        let p = ap_pdu(MessageKind::Initiating, 0);
        let r = dissect_sabp(None, None, 1234, 5678, &p);
        assert_eq!(r.protocol, Protocol::Sabp);
        assert_eq!(r.summary, "SABP Write-Replace");
    }

    #[test]
    fn successful_outcome_is_labelled() {
        let p = ap_pdu(MessageKind::SuccessfulOutcome, 0);
        let r = dissect_sabp(None, None, 1234, 5678, &p);
        assert_eq!(r.summary, "SABP Write-Replace (success)");
    }

    #[test]
    fn unknown_procedure_reports_its_code() {
        let p = ap_pdu(MessageKind::Initiating, 251);
        let r = dissect_sabp(None, None, 1234, 5678, &p);
        assert_eq!(r.summary, "SABP procedure 251 [reject]");
    }

    #[test]
    fn truncated_payload_does_not_panic() {
        let r = dissect_sabp(None, None, 1234, 5678, &[0x00]);
        assert_eq!(r.summary, "SABP (1 byte)");
    }
}
