// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{ngap_common, DissectedResult};

/// RNSAP procedure codes (3GPP TS 25.423).
fn procedure(code: u8) -> Option<&'static str> {
    Some(match code {
        0 => "RadioLinkSetup",
        1 => "RadioLinkAddition",
        2 => "RadioLinkDeletion",
        3 => "ReconfigurationPreparation",
        4 => "ReconfigurationCommit",
        5 => "ReconfigurationCancel",
        6 => "PhysicalChannelReconfiguration",
        7 => "RadioLinkFailure",
        8 => "RadioLinkRestoration",
        9 => "DedicatedMeasurementInitiation",
        10 => "DedicatedMeasurementReporting",
        11 => "DedicatedMeasurementTermination",
        12 => "DedicatedMeasurementFailure",
        13 => "DownlinkPowerControl",
        14 => "CommonTransportChannelResourcesInitialisation",
        15 => "CommonTransportChannelResourcesRelease",
        16 => "CompressedModeCommand",
        17 => "ErrorIndication",
        18 => "CommonMeasurementInitiation",
        19 => "CommonMeasurementReporting",
        20 => "CommonMeasurementTermination",
        21 => "CommonMeasurementFailure",
        22 => "Reset",
        23 => "PagingRequest",
        24 => "CommonTransportChannelResourcesFailure",
        25 => "InformationExchangeInitiation",
        26 => "InformationReporting",
        27 => "InformationExchangeTermination",
        28 => "InformationExchangeFailure",
        29 => "PrivateMessage",
        _ => return None,
    })
}

/// Dissect a RNSAP message — RNSAP is the 3G Iur interface between two radio network controllers,
/// carried inside SCCP and identified by subsystem number 143 rather than
/// by any port or SCTP identifier of its own (3GPP TS 25.423).
pub fn dissect_rnsap(
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
        protocol: Protocol::Rnsap,
        summary: ngap_common::summarize("RNSAP", payload, procedure),
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
        let r = dissect_rnsap(None, None, 1234, 5678, &p);
        assert_eq!(r.protocol, Protocol::Rnsap);
        assert_eq!(r.summary, "RNSAP RadioLinkSetup");
    }

    #[test]
    fn successful_outcome_is_labelled() {
        let p = ap_pdu(MessageKind::SuccessfulOutcome, 0);
        let r = dissect_rnsap(None, None, 1234, 5678, &p);
        assert_eq!(r.summary, "RNSAP RadioLinkSetup (success)");
    }

    #[test]
    fn unknown_procedure_reports_its_code() {
        let p = ap_pdu(MessageKind::Initiating, 251);
        let r = dissect_rnsap(None, None, 1234, 5678, &p);
        assert_eq!(r.summary, "RNSAP procedure 251 [reject]");
    }

    #[test]
    fn truncated_payload_does_not_panic() {
        let r = dissect_rnsap(None, None, 1234, 5678, &[0x00]);
        assert_eq!(r.summary, "RNSAP (1 byte)");
    }
}
