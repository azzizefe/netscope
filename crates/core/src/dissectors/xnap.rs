// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::{ngap_common, DissectedResult};

/// XnAP procedure codes (3GPP TS 38.423 §9.3.1.2). Xn is the direct link
/// between two gNBs, used mostly to hand a phone from one cell to the next
/// without routing through the core.
fn procedure(code: u8) -> Option<&'static str> {
    Some(match code {
        0 => "HandoverPreparation",
        1 => "SNStatusTransfer",
        2 => "HandoverCancel",
        3 => "RetrieveUEContext",
        4 => "RANPaging",
        5 => "XnUAddressIndication",
        6 => "UEContextRelease",
        7 => "SNGRANnodeAdditionPreparation",
        8 => "SNGRANnodeReconfigurationCompletion",
        9 => "MNGRANnodeinitiatedSNGRANnodeModificationPreparation",
        10 => "SNGRANnodeinitiatedSNGRANnodeModificationPreparation",
        11 => "MNGRANnodeinitiatedSNGRANnodeRelease",
        12 => "SNGRANnodeinitiatedSNGRANnodeRelease",
        13 => "SNGRANnodeCounterCheck",
        14 => "RRCTransfer",
        15 => "XnSetup",
        16 => "NGRANnodeConfigurationUpdate",
        17 => "E-UTRA-NRCellResourceCoordination",
        18 => "XnRemoval",
        19 => "CellActivation",
        20 => "Reset",
        21 => "ErrorIndication",
        22 => "PrivateMessage",
        23 => "NotificationControl",
        24 => "ActivityNotification",
        25 => "SecondaryRATDataUsageReport",
        _ => return None,
    })
}

/// Dissect an XnAP message — gNB-to-gNB signalling over SCTP with payload
/// protocol identifier 61 (3GPP TS 38.423).
pub fn dissect_xnap(
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
        protocol: Protocol::Xnap,
        summary: ngap_common::summarize("XnAP", payload, procedure),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissectors::ngap_common::test_helpers::ap_pdu;
    use crate::dissectors::ngap_common::MessageKind;

    #[test]
    fn handover_preparation() {
        let p = ap_pdu(MessageKind::Initiating, 0);
        let r = dissect_xnap(None, None, 38422, 38422, &p);
        assert_eq!(r.protocol, Protocol::Xnap);
        assert_eq!(r.summary, "XnAP HandoverPreparation");
    }

    #[test]
    fn xn_setup_success() {
        let p = ap_pdu(MessageKind::SuccessfulOutcome, 15);
        let r = dissect_xnap(None, None, 38422, 38422, &p);
        assert_eq!(r.summary, "XnAP XnSetup (success)");
    }
}
