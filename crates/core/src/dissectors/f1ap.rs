// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{ngap_common, DissectedResult};

/// F1AP procedure codes (3GPP TS 38.473 §9.3.1.1). F1 splits a gNB into a
/// central unit and one or more distributed units; this is the link between
/// them, so it shows up inside a single RAN deployment rather than on an
/// operator interconnect.
fn procedure(code: u8) -> Option<&'static str> {
    Some(match code {
        0 => "Reset",
        1 => "F1Setup",
        2 => "ErrorIndication",
        3 => "gNBDUConfigurationUpdate",
        4 => "gNBCUConfigurationUpdate",
        5 => "UEContextSetup",
        6 => "UEContextRelease",
        7 => "UEContextModification",
        8 => "UEContextModificationRequired",
        9 => "UEMobilityCommand",
        10 => "UEContextReleaseRequest",
        11 => "InitialULRRCMessageTransfer",
        12 => "DLRRCMessageTransfer",
        13 => "ULRRCMessageTransfer",
        14 => "PrivateMessage",
        15 => "UEInactivityNotification",
        16 => "GNBDUResourceCoordination",
        17 => "SystemInformationDeliveryCommand",
        18 => "Paging",
        19 => "Notify",
        20 => "WriteReplaceWarning",
        21 => "PWSCancel",
        22 => "PWSRestartIndication",
        23 => "PWSFailureIndication",
        24 => "GNBDUStatusIndication",
        25 => "RRCDeliveryReport",
        26 => "F1Removal",
        27 => "NetworkAccessRateReduction",
        28 => "TraceStart",
        29 => "DeactivateTrace",
        30 => "DUCURadioInformationTransfer",
        31 => "CUDURadioInformationTransfer",
        _ => return None,
    })
}

/// Dissect an F1AP message — gNB-CU to gNB-DU signalling over SCTP with payload
/// protocol identifier 62 (3GPP TS 38.473).
pub fn dissect_f1ap(
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
        protocol: Protocol::F1ap,
        summary: ngap_common::summarize("F1AP", payload, procedure),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissectors::ngap_common::test_helpers::ap_pdu;
    use crate::dissectors::ngap_common::MessageKind;

    #[test]
    fn f1_setup() {
        let p = ap_pdu(MessageKind::Initiating, 1);
        let r = dissect_f1ap(None, None, 38472, 38472, &p);
        assert_eq!(r.protocol, Protocol::F1ap);
        assert_eq!(r.summary, "F1AP F1Setup");
    }

    #[test]
    fn ue_context_setup_success() {
        let p = ap_pdu(MessageKind::SuccessfulOutcome, 5);
        let r = dissect_f1ap(None, None, 38472, 38472, &p);
        assert_eq!(r.summary, "F1AP UEContextSetup (success)");
    }
}
