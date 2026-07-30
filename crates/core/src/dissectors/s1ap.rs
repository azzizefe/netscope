// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{ngap_common, DissectedResult};

/// S1AP procedure codes (3GPP TS 36.413 §9.3.1.2) — the LTE equivalent of
/// NGAP's list, between an eNB and the MME.
fn procedure(code: u8) -> Option<&'static str> {
    Some(match code {
        0 => "HandoverPreparation",
        1 => "HandoverResourceAllocation",
        2 => "HandoverNotification",
        3 => "PathSwitchRequest",
        4 => "HandoverCancel",
        5 => "E-RABSetup",
        6 => "E-RABModify",
        7 => "E-RABRelease",
        8 => "E-RABReleaseIndication",
        9 => "InitialContextSetup",
        10 => "Paging",
        11 => "DownlinkNASTransport",
        12 => "InitialUEMessage",
        13 => "UplinkNASTransport",
        14 => "Reset",
        15 => "ErrorIndication",
        16 => "NASNonDeliveryIndication",
        17 => "S1Setup",
        18 => "UEContextReleaseRequest",
        19 => "DownlinkS1cdma2000tunnelling",
        20 => "UplinkS1cdma2000tunnelling",
        21 => "UEContextModification",
        22 => "UECapabilityInfoIndication",
        23 => "UEContextRelease",
        24 => "eNBStatusTransfer",
        25 => "MMEStatusTransfer",
        26 => "DeactivateTrace",
        27 => "TraceStart",
        28 => "TraceFailureIndication",
        29 => "ENBConfigurationUpdate",
        30 => "MMEConfigurationUpdate",
        31 => "LocationReportingControl",
        32 => "LocationReportingFailureIndication",
        33 => "LocationReport",
        34 => "OverloadStart",
        35 => "OverloadStop",
        36 => "WriteReplaceWarning",
        37 => "eNBDirectInformationTransfer",
        38 => "MMEDirectInformationTransfer",
        39 => "PrivateMessage",
        40 => "eNBConfigurationTransfer",
        41 => "MMEConfigurationTransfer",
        42 => "CellTrafficTrace",
        43 => "Kill",
        44 => "DownlinkUEAssociatedLPPaTransport",
        45 => "UplinkUEAssociatedLPPaTransport",
        46 => "DownlinkNonUEAssociatedLPPaTransport",
        47 => "UplinkNonUEAssociatedLPPaTransport",
        48 => "UERadioCapabilityMatch",
        49 => "PWSRestartIndication",
        50 => "E-RABModificationIndication",
        51 => "PWSFailureIndication",
        52 => "RerouteNASRequest",
        53 => "UEContextModificationIndication",
        54 => "ConnectionEstablishmentIndication",
        _ => return None,
    })
}

/// Dissect an S1AP message — the LTE control plane between an eNB and the MME,
/// carried over SCTP with payload protocol identifier 18 (3GPP TS 36.413).
pub fn dissect_s1ap(
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
        protocol: Protocol::S1ap,
        summary: ngap_common::summarize("S1AP", payload, procedure),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissectors::ngap_common::test_helpers::ap_pdu;
    use crate::dissectors::ngap_common::MessageKind;

    #[test]
    fn initial_ue_message() {
        let p = ap_pdu(MessageKind::Initiating, 12);
        let r = dissect_s1ap(None, None, 36412, 36412, &p);
        assert_eq!(r.protocol, Protocol::S1ap);
        assert_eq!(r.summary, "S1AP InitialUEMessage");
    }

    #[test]
    fn s1_setup_success() {
        let p = ap_pdu(MessageKind::SuccessfulOutcome, 17);
        let r = dissect_s1ap(None, None, 36412, 36412, &p);
        assert_eq!(r.summary, "S1AP S1Setup (success)");
    }

    /// S1AP and NGAP share the header layout but not the code list — code 15 is
    /// InitialUEMessage in NGAP and ErrorIndication in S1AP. Getting these
    /// crossed would mislabel real traffic, so pin it.
    #[test]
    fn procedure_codes_are_not_ngaps() {
        let p = ap_pdu(MessageKind::Initiating, 15);
        let r = dissect_s1ap(None, None, 36412, 36412, &p);
        assert_eq!(r.summary, "S1AP ErrorIndication");
    }
}
