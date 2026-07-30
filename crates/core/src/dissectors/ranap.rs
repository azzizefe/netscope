// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{ngap_common, DissectedResult};

/// RANAP procedure codes (3GPP TS 25.413).
fn procedure(code: u8) -> Option<&'static str> {
    Some(match code {
        0 => "RAB-Assignment",
        1 => "Iu-Release",
        2 => "RelocationPreparation",
        3 => "RelocationResourceAllocation",
        4 => "RelocationCancel",
        5 => "SRNS-ContextTransfer",
        6 => "SecurityModeControl",
        7 => "DataVolumeReport",
        9 => "Reset",
        10 => "RAB-ReleaseRequest",
        11 => "Iu-ReleaseRequest",
        12 => "RelocationDetect",
        13 => "RelocationComplete",
        14 => "Paging",
        15 => "CommonID",
        16 => "CN-InvokeTrace",
        17 => "LocationReportingControl",
        18 => "LocationReport",
        19 => "InitialUE-Message",
        20 => "DirectTransfer",
        21 => "OverloadControl",
        22 => "ErrorIndication",
        23 => "SRNS-DataForward",
        24 => "ForwardSRNS-Context",
        25 => "PrivateMessage",
        26 => "CN-DeactivateTrace",
        27 => "ResetResource",
        28 => "RANAP-Relocation",
        29 => "RAB-ModifyRequest",
        30 => "LocationRelatedData",
        31 => "InformationTransfer",
        32 => "UESpecificInformation",
        33 => "UplinkInformationExchange",
        34 => "DirectInformationTransfer",
        35 => "MBMSSessionStart",
        36 => "MBMSSessionUpdate",
        37 => "MBMSSessionStop",
        38 => "MBMSUELinking",
        39 => "MBMSRegistration",
        40 => "MBMSCNDe-Registration",
        41 => "MBMSRABEstablishmentIndication",
        42 => "MBMSRABRelease",
        _ => return None,
    })
}

/// Dissect a RANAP message — RANAP is the 3G Iu interface between the radio network controller and the core,
/// carried inside SCCP and identified by subsystem number 142 rather than
/// by any port or SCTP identifier of its own (3GPP TS 25.413).
pub fn dissect_ranap(
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
        protocol: Protocol::Ranap,
        summary: ngap_common::summarize("RANAP", payload, procedure),
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
        let r = dissect_ranap(None, None, 1234, 5678, &p);
        assert_eq!(r.protocol, Protocol::Ranap);
        assert_eq!(r.summary, "RANAP RAB-Assignment");
    }

    #[test]
    fn successful_outcome_is_labelled() {
        let p = ap_pdu(MessageKind::SuccessfulOutcome, 0);
        let r = dissect_ranap(None, None, 1234, 5678, &p);
        assert_eq!(r.summary, "RANAP RAB-Assignment (success)");
    }

    #[test]
    fn unknown_procedure_reports_its_code() {
        let p = ap_pdu(MessageKind::Initiating, 251);
        let r = dissect_ranap(None, None, 1234, 5678, &p);
        assert_eq!(r.summary, "RANAP procedure 251 [reject]");
    }

    #[test]
    fn truncated_payload_does_not_panic() {
        let r = dissect_ranap(None, None, 1234, 5678, &[0x00]);
        assert_eq!(r.summary, "RANAP (1 byte)");
    }
}
