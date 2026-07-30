// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{ngap_common, DissectedResult};

/// LCS-AP procedure codes (3GPP TS 29.171).
fn procedure(code: u8) -> Option<&'static str> {
    Some(match code {
        0 => "LocationService",
        1 => "ConnectionOrientedInformationTransfer",
        2 => "ConnectionlessInformationTransfer",
        3 => "LocationAbort",
        4 => "Reset",
        5 => "Ciphering-Key-Data-Delivery",
        _ => return None,
    })
}

/// Dissect a LCS-AP message — locates a phone for emergency services and lawful intercept, carried over
/// SCTP with payload protocol identifier 29 (3GPP TS 29.171).
pub fn dissect_lcsap(
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
        protocol: Protocol::LcsAp,
        summary: ngap_common::summarize("LCS-AP", payload, procedure),
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
        let r = dissect_lcsap(None, None, 1234, 5678, &p);
        assert_eq!(r.protocol, Protocol::LcsAp);
        assert_eq!(r.summary, "LCS-AP LocationService");
    }

    #[test]
    fn successful_outcome_is_labelled() {
        let p = ap_pdu(MessageKind::SuccessfulOutcome, 0);
        let r = dissect_lcsap(None, None, 1234, 5678, &p);
        assert_eq!(r.summary, "LCS-AP LocationService (success)");
    }

    #[test]
    fn unknown_procedure_reports_its_code() {
        let p = ap_pdu(MessageKind::Initiating, 251);
        let r = dissect_lcsap(None, None, 1234, 5678, &p);
        assert_eq!(r.summary, "LCS-AP procedure 251 [reject]");
    }

    #[test]
    fn truncated_payload_does_not_panic() {
        let r = dissect_lcsap(None, None, 1234, 5678, &[0x00]);
        assert_eq!(r.summary, "LCS-AP (1 byte)");
    }
}
