// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{ngap_common, DissectedResult};

/// RUA procedure codes (3GPP TS 25.468).
fn procedure(code: u8) -> Option<&'static str> {
    Some(match code {
        1 => "Connect",
        2 => "DirectTransfer",
        3 => "Disconnect",
        4 => "ConnectionlessTransfer",
        5 => "ErrorIndication",
        6 => "PrivateMessage",
        _ => return None,
    })
}

/// Dissect a RUA message — carries RANAP between a home NodeB (femtocell) and its gateway, carried over
/// SCTP with payload protocol identifier 19 (3GPP TS 25.468).
pub fn dissect_rua(
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
        protocol: Protocol::Rua,
        summary: ngap_common::summarize("RUA", payload, procedure),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissectors::ngap_common::test_helpers::ap_pdu;
    use crate::dissectors::ngap_common::MessageKind;

    #[test]
    fn first_procedure_is_named() {
        let p = ap_pdu(MessageKind::Initiating, 1);
        let r = dissect_rua(None, None, 1234, 5678, &p);
        assert_eq!(r.protocol, Protocol::Rua);
        assert_eq!(r.summary, "RUA Connect");
    }

    #[test]
    fn successful_outcome_is_labelled() {
        let p = ap_pdu(MessageKind::SuccessfulOutcome, 1);
        let r = dissect_rua(None, None, 1234, 5678, &p);
        assert_eq!(r.summary, "RUA Connect (success)");
    }

    #[test]
    fn unknown_procedure_reports_its_code() {
        let p = ap_pdu(MessageKind::Initiating, 251);
        let r = dissect_rua(None, None, 1234, 5678, &p);
        assert_eq!(r.summary, "RUA procedure 251 [reject]");
    }

    #[test]
    fn truncated_payload_does_not_panic() {
        let r = dissect_rua(None, None, 1234, 5678, &[0x00]);
        assert_eq!(r.summary, "RUA (1 byte)");
    }
}
