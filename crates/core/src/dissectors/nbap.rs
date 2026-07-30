// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{ngap_common, DissectedResult};

/// NBAP procedure codes (3GPP TS 25.433).
fn procedure(code: u8) -> Option<&'static str> {
    Some(match code {
        0 => "CellSetup",
        1 => "CellReconfiguration",
        2 => "CellDeletion",
        3 => "CommonTransportChannelSetup",
        4 => "CommonTransportChannelReconfigure",
        5 => "CommonTransportChannelDelete",
        6 => "AuditRequired",
        7 => "Audit",
        8 => "BlockResource",
        9 => "CommonMeasurementInitiation",
        10 => "CommonMeasurementReport",
        11 => "CommonMeasurementTermination",
        12 => "CommonMeasurementFailure",
        13 => "ErrorIndication",
        19 => "RadioLinkAddition",
        20 => "RadioLinkDeletion",
        21 => "RadioLinkFailure",
        22 => "RadioLinkRestoration",
        23 => "RadioLinkSetup",
        25 => "ResourceStatusIndication",
        26 => "SystemInformationUpdate",
        27 => "UnblockResource",
        28 => "UnsynchronisedRadioLinkReconfiguration",
        _ => return None,
    })
}

/// Dissect a NBAP message — is the 3G Iub interface between a NodeB and its radio network controller, carried over
/// SCTP with payload protocol identifier 25 (3GPP TS 25.433).
pub fn dissect_nbap(
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
        protocol: Protocol::Nbap,
        summary: ngap_common::summarize("NBAP", payload, procedure),
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
        let r = dissect_nbap(None, None, 1234, 5678, &p);
        assert_eq!(r.protocol, Protocol::Nbap);
        assert_eq!(r.summary, "NBAP CellSetup");
    }

    #[test]
    fn successful_outcome_is_labelled() {
        let p = ap_pdu(MessageKind::SuccessfulOutcome, 0);
        let r = dissect_nbap(None, None, 1234, 5678, &p);
        assert_eq!(r.summary, "NBAP CellSetup (success)");
    }

    #[test]
    fn unknown_procedure_reports_its_code() {
        let p = ap_pdu(MessageKind::Initiating, 251);
        let r = dissect_nbap(None, None, 1234, 5678, &p);
        assert_eq!(r.summary, "NBAP procedure 251 [reject]");
    }

    #[test]
    fn truncated_payload_does_not_panic() {
        let r = dissect_nbap(None, None, 1234, 5678, &[0x00]);
        assert_eq!(r.summary, "NBAP (1 byte)");
    }
}
