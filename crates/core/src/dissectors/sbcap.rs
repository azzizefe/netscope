// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{ngap_common, DissectedResult};

/// SBc-AP procedure codes (3GPP TS 29.168).
fn procedure(code: u8) -> Option<&'static str> {
    Some(match code {
        0 => "WriteReplaceWarning",
        1 => "StopWarning",
        2 => "ErrorIndication",
        3 => "WriteReplaceWarningIndication",
        4 => "StopWarningIndication",
        5 => "PWSRestartIndication",
        6 => "PWSFailureIndication",
        _ => return None,
    })
}

/// Dissect a SBc-AP message — delivers public warning messages (earthquake, tsunami, amber alerts) to LTE cells, carried over
/// SCTP with payload protocol identifier 24 (3GPP TS 29.168).
pub fn dissect_sbcap(
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
        protocol: Protocol::SbcAp,
        summary: ngap_common::summarize("SBc-AP", payload, procedure),
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
        let r = dissect_sbcap(None, None, 1234, 5678, &p);
        assert_eq!(r.protocol, Protocol::SbcAp);
        assert_eq!(r.summary, "SBc-AP WriteReplaceWarning");
    }

    #[test]
    fn successful_outcome_is_labelled() {
        let p = ap_pdu(MessageKind::SuccessfulOutcome, 0);
        let r = dissect_sbcap(None, None, 1234, 5678, &p);
        assert_eq!(r.summary, "SBc-AP WriteReplaceWarning (success)");
    }

    #[test]
    fn unknown_procedure_reports_its_code() {
        let p = ap_pdu(MessageKind::Initiating, 251);
        let r = dissect_sbcap(None, None, 1234, 5678, &p);
        assert_eq!(r.summary, "SBc-AP procedure 251 [reject]");
    }

    #[test]
    fn truncated_payload_does_not_panic() {
        let r = dissect_sbcap(None, None, 1234, 5678, &[0x00]);
        assert_eq!(r.summary, "SBc-AP (1 byte)");
    }
}
