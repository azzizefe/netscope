// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{ngap_common, DissectedResult};

/// E1AP procedure codes (3GPP TS 38.463 §9.3.1.1). E1 splits the gNB central
/// unit itself into a control-plane and a user-plane half; this is the link
/// between those two.
fn procedure(code: u8) -> Option<&'static str> {
    Some(match code {
        0 => "Reset",
        1 => "ErrorIndication",
        2 => "PrivateMessage",
        3 => "GNBCUUPE1Setup",
        4 => "GNBCUCPE1Setup",
        5 => "GNBCUUPConfigurationUpdate",
        6 => "GNBCUCPConfigurationUpdate",
        7 => "E1Release",
        8 => "BearerContextSetup",
        9 => "BearerContextModification",
        10 => "BearerContextModificationRequired",
        11 => "BearerContextRelease",
        12 => "BearerContextReleaseRequest",
        13 => "BearerContextInactivityNotification",
        14 => "DLDataNotification",
        15 => "DataUsageReport",
        16 => "GNBCUUPCounterCheck",
        17 => "GNBCUUPStatusIndication",
        18 => "ULDataNotification",
        19 => "MRDCDataUsageReport",
        20 => "TraceStart",
        21 => "DeactivateTrace",
        22 => "ResourceStatusReportingInitiation",
        23 => "ResourceStatusReporting",
        _ => return None,
    })
}

/// Dissect an E1AP message — gNB-CU-CP to gNB-CU-UP signalling over SCTP with
/// payload protocol identifier 64 (3GPP TS 38.463).
pub fn dissect_e1ap(
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
        protocol: Protocol::E1ap,
        summary: ngap_common::summarize("E1AP", payload, procedure),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissectors::ngap_common::test_helpers::ap_pdu;
    use crate::dissectors::ngap_common::MessageKind;

    #[test]
    fn bearer_context_setup() {
        let p = ap_pdu(MessageKind::Initiating, 8);
        let r = dissect_e1ap(None, None, 38462, 38462, &p);
        assert_eq!(r.protocol, Protocol::E1ap);
        assert_eq!(r.summary, "E1AP BearerContextSetup");
    }

    #[test]
    fn unknown_release_procedure_still_informative() {
        let p = ap_pdu(MessageKind::Initiating, 250);
        let r = dissect_e1ap(None, None, 38462, 38462, &p);
        assert_eq!(r.summary, "E1AP procedure 250 [reject]");
    }
}
