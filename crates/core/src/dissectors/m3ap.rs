// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{ngap_common, DissectedResult};

/// M3AP procedure codes (3GPP TS 36.444).
fn procedure(code: u8) -> Option<&'static str> {
    Some(match code {
        0 => "SessionStart",
        1 => "SessionStop",
        2 => "ErrorIndication",
        3 => "PrivateMessage",
        4 => "SessionUpdate",
        5 => "Reset",
        6 => "M3Setup",
        7 => "MCEConfigurationUpdate",
        _ => return None,
    })
}

/// Dissect a M3AP message — connects the MCE to the MBMS gateway for multicast/broadcast sessions, carried over
/// SCTP with payload protocol identifier 44 (3GPP TS 36.444).
pub fn dissect_m3ap(
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
        protocol: Protocol::M3ap,
        summary: ngap_common::summarize("M3AP", payload, procedure),
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
        let r = dissect_m3ap(None, None, 1234, 5678, &p);
        assert_eq!(r.protocol, Protocol::M3ap);
        assert_eq!(r.summary, "M3AP SessionStart");
    }

    #[test]
    fn successful_outcome_is_labelled() {
        let p = ap_pdu(MessageKind::SuccessfulOutcome, 0);
        let r = dissect_m3ap(None, None, 1234, 5678, &p);
        assert_eq!(r.summary, "M3AP SessionStart (success)");
    }

    #[test]
    fn unknown_procedure_reports_its_code() {
        let p = ap_pdu(MessageKind::Initiating, 251);
        let r = dissect_m3ap(None, None, 1234, 5678, &p);
        assert_eq!(r.summary, "M3AP procedure 251 [reject]");
    }

    #[test]
    fn truncated_payload_does_not_panic() {
        let r = dissect_m3ap(None, None, 1234, 5678, &[0x00]);
        assert_eq!(r.summary, "M3AP (1 byte)");
    }
}
