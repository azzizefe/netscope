// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{ngap_common, DissectedResult};

/// NGAP procedure codes (3GPP TS 38.413 §9.3.1.2). These name what the gNB and
/// the AMF are doing to each other — registering a phone, setting up a PDU
/// session, handing it over to another cell.
fn procedure(code: u8) -> Option<&'static str> {
    Some(match code {
        0 => "AMFConfigurationUpdate",
        1 => "AMFStatusIndication",
        2 => "CellTrafficTrace",
        3 => "DeactivateTrace",
        4 => "DownlinkNASTransport",
        5 => "DownlinkNonUEAssociatedNRPPaTransport",
        6 => "DownlinkRANConfigurationTransfer",
        7 => "DownlinkRANStatusTransfer",
        8 => "DownlinkUEAssociatedNRPPaTransport",
        9 => "ErrorIndication",
        10 => "HandoverCancel",
        11 => "HandoverNotification",
        12 => "HandoverPreparation",
        13 => "HandoverResourceAllocation",
        14 => "InitialContextSetup",
        15 => "InitialUEMessage",
        16 => "LocationReportingControl",
        17 => "LocationReportingFailureIndication",
        18 => "LocationReport",
        19 => "NASNonDeliveryIndication",
        20 => "NGReset",
        21 => "NGSetup",
        22 => "OverloadStart",
        23 => "OverloadStop",
        24 => "Paging",
        25 => "PathSwitchRequest",
        26 => "PDUSessionResourceModify",
        27 => "PDUSessionResourceModifyIndication",
        28 => "PDUSessionResourceRelease",
        29 => "PDUSessionResourceSetup",
        30 => "PDUSessionResourceNotify",
        31 => "PrivateMessage",
        32 => "PWSCancel",
        33 => "PWSFailureIndication",
        34 => "PWSRestartIndication",
        35 => "RANConfigurationUpdate",
        36 => "RerouteNASRequest",
        37 => "RRCInactiveTransitionReport",
        38 => "TraceFailureIndication",
        39 => "TraceStart",
        40 => "UEContextModification",
        41 => "UEContextRelease",
        42 => "UEContextReleaseRequest",
        43 => "UERadioCapabilityCheck",
        44 => "UERadioCapabilityInfoIndication",
        45 => "UETNLABindingRelease",
        46 => "UplinkNASTransport",
        47 => "UplinkNonUEAssociatedNRPPaTransport",
        48 => "UplinkRANConfigurationTransfer",
        49 => "UplinkRANStatusTransfer",
        50 => "UplinkUEAssociatedNRPPaTransport",
        51 => "WriteReplaceWarning",
        52 => "SecondaryRATDataUsageReport",
        _ => return None,
    })
}

/// Dissect an NGAP message — the 5G control plane between a gNB (radio) and the
/// AMF (core), carried over SCTP with payload protocol identifier 60
/// (3GPP TS 38.413).
pub fn dissect_ngap(
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
        protocol: Protocol::Ngap,
        summary: ngap_common::summarize("NGAP", payload, procedure),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissectors::ngap_common::test_helpers::ap_pdu;
    use crate::dissectors::ngap_common::MessageKind;

    #[test]
    fn initial_ue_message() {
        let p = ap_pdu(MessageKind::Initiating, 15);
        let r = dissect_ngap(None, None, 38412, 38412, &p);
        assert_eq!(r.protocol, Protocol::Ngap);
        assert_eq!(r.summary, "NGAP InitialUEMessage");
    }

    #[test]
    fn ng_setup_response() {
        let p = ap_pdu(MessageKind::SuccessfulOutcome, 21);
        let r = dissect_ngap(None, None, 38412, 38412, &p);
        assert_eq!(r.summary, "NGAP NGSetup (success)");
    }

    #[test]
    fn pdu_session_setup_failure() {
        let p = ap_pdu(MessageKind::UnsuccessfulOutcome, 29);
        let r = dissect_ngap(None, None, 38412, 38412, &p);
        assert_eq!(r.summary, "NGAP PDUSessionResourceSetup (failure)");
    }

    #[test]
    fn truncated_payload_is_reported_not_panicked() {
        let r = dissect_ngap(None, None, 38412, 38412, &[0x00]);
        assert_eq!(r.summary, "NGAP (1 byte)");
    }
}
