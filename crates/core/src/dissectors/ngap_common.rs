// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! The header every 3GPP application protocol shares.
//!
//! NGAP, S1AP, RANAP, XnAP, F1AP and the rest of the family are separate
//! specifications, but they are all ASN.1 aligned-PER and they all open the
//! same way: an extensible CHOICE of three alternatives, then the procedure
//! code, then the criticality — what the receiver must do if it does not
//! understand the procedure.
//!
//! Aligned PER gives each of those its own octet, so the first three bytes say
//! what a PDU *is* without decoding the body at all:
//!
//! ```text
//!   00   15   00   3c  ...
//!   |    |    |    `--- length of the open type (the body, not read here)
//!   |    |    `-------- criticality, top 2 bits: 0 reject, 1 ignore, 2 notify
//!   |    `------------- procedure code — 21, NGSetup
//!   `------------------ choice index, top 3 bits: initiatingMessage
//! ```
//!
//! That is a real NGSetupRequest off the wire. Decoding the body would mean a
//! full PER decoder for each of six specifications; decoding the header means
//! every one of them can say which procedure is running, which is the thing
//! worth knowing from a packet list.
//!
//! ## The procedure lists are not interchangeable
//!
//! Each dissector passes its own code table and shares everything else. The
//! tables must stay separate: code 15 is `InitialUEMessage` in NGAP and
//! `ErrorIndication` in S1AP, so crossing them mislabels real traffic rather
//! than failing visibly.

use super::bytes;

/// Which of the three outcomes a PDU carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    Initiating,
    SuccessfulOutcome,
    UnsuccessfulOutcome,
}

impl MessageKind {
    /// The APER choice index lives in the top three bits of the first octet:
    /// one extension bit (always 0 for the three root alternatives) followed by
    /// a two-bit index.
    fn from_first_octet(octet: u8) -> Option<Self> {
        match octet >> 5 {
            0 => Some(Self::Initiating),
            1 => Some(Self::SuccessfulOutcome),
            2 => Some(Self::UnsuccessfulOutcome),
            _ => None,
        }
    }

    /// The same index, written back out. Used by the test helper.
    #[cfg(test)]
    fn first_octet(self) -> u8 {
        match self {
            Self::Initiating => 0x00,
            Self::SuccessfulOutcome => 0x20,
            Self::UnsuccessfulOutcome => 0x40,
        }
    }

    /// How the outcome reads after the procedure name. An initiating message
    /// is the unmarked case — it is the request, and saying so adds nothing.
    fn suffix(self) -> &'static str {
        match self {
            Self::Initiating => "",
            Self::SuccessfulOutcome => " (success)",
            Self::UnsuccessfulOutcome => " (failure)",
        }
    }
}

/// Criticality — what the receiver does with a procedure it does not know.
///
/// Worth showing on an unrecognised code specifically: a `reject` the decoder
/// could not name is a procedure the peer is required to refuse, which is a
/// different situation from one it is allowed to skip past.
fn criticality(octet: u8) -> &'static str {
    match octet >> 6 {
        0 => "reject",
        1 => "ignore",
        _ => "notify",
    }
}

/// Choice index, procedure code, criticality.
const HEADER: usize = 3;

/// Summarise an AP PDU using the caller's procedure-code table.
pub fn summarize(
    name: &str,
    payload: &[u8],
    procedure_fn: fn(u8) -> Option<&'static str>,
) -> String {
    // Too short to hold a header — report the size rather than reading bytes
    // that are not there.
    let Some(head) = payload.get(..HEADER) else {
        return format!("{name} ({})", bytes(payload.len() as u64));
    };
    let Some(kind) = MessageKind::from_first_octet(head[0]) else {
        // The extension bit is set, or the index names an alternative that does
        // not exist. Either way this is not a PDU the family defines.
        return format!("{name} (unrecognised PDU)");
    };

    match procedure_fn(head[1]) {
        Some(procedure) => format!("{name} {procedure}{}", kind.suffix()),
        // An unknown code is not a decode failure — the family gains procedures
        // by release, and a newer one on an older build lands here. The code and
        // its criticality are what identify it.
        None => format!("{name} procedure {} [{}]", head[1], criticality(head[2])),
    }
}

#[cfg(test)]
pub mod test_helpers {
    use super::{MessageKind, HEADER};

    /// Build the header of an AP PDU, as [`summarize`](super::summarize) reads
    /// it: choice index, procedure code, criticality `reject`.
    ///
    /// The body is left off. Nothing here decodes it, and a PDU carrying only
    /// its header is the smallest input that exercises the path.
    pub fn ap_pdu(kind: MessageKind, procedure: u16) -> Vec<u8> {
        let mut pdu = Vec::with_capacity(HEADER);
        pdu.push(kind.first_octet());
        pdu.push(procedure as u8);
        pdu.push(0x00); // criticality: reject
        pdu
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::ap_pdu;
    use super::*;

    /// A stand-in for a real dissector's table.
    fn procedure(code: u8) -> Option<&'static str> {
        match code {
            21 => Some("NGSetup"),
            _ => None,
        }
    }

    /// The header of a real NGSetupRequest, taken off the wire. If the octet
    /// layout is ever misread, this is what catches it.
    #[test]
    fn a_real_ng_setup_request_is_named() {
        let pdu = [0x00, 0x15, 0x00, 0x3C, 0x00, 0x00, 0x04];
        assert_eq!(summarize("NGAP", &pdu, procedure), "NGAP NGSetup");
    }

    /// The outcome is the difference between a request and its answer, and the
    /// two answers have to be told apart from each other.
    #[test]
    fn each_outcome_is_labelled() {
        let init = ap_pdu(MessageKind::Initiating, 21);
        let ok = ap_pdu(MessageKind::SuccessfulOutcome, 21);
        let fail = ap_pdu(MessageKind::UnsuccessfulOutcome, 21);
        assert_eq!(summarize("NGAP", &init, procedure), "NGAP NGSetup");
        assert_eq!(summarize("NGAP", &ok, procedure), "NGAP NGSetup (success)");
        assert_eq!(
            summarize("NGAP", &fail, procedure),
            "NGAP NGSetup (failure)"
        );
    }

    /// A procedure from a later release than this table knows still reports
    /// what it was — the code, and whether the peer must refuse it.
    #[test]
    fn an_unknown_procedure_reports_its_code_and_criticality() {
        assert_eq!(
            summarize("NGAP", &[0x00, 0xFB, 0x00], procedure),
            "NGAP procedure 251 [reject]"
        );
        assert_eq!(
            summarize("NGAP", &[0x00, 0xFB, 0x40], procedure),
            "NGAP procedure 251 [ignore]"
        );
        assert_eq!(
            summarize("NGAP", &[0x00, 0xFB, 0x80], procedure),
            "NGAP procedure 251 [notify]"
        );
    }

    /// Short payloads are reported at their real size, singular included.
    #[test]
    fn a_truncated_pdu_reports_its_size() {
        assert_eq!(summarize("NGAP", &[], procedure), "NGAP (0 bytes)");
        assert_eq!(summarize("NGAP", &[0x00], procedure), "NGAP (1 byte)");
        assert_eq!(
            summarize("NGAP", &[0x00, 0x15], procedure),
            "NGAP (2 bytes)"
        );
    }

    /// An index past the three defined alternatives is not an AP PDU. Reading
    /// byte 1 anyway would name a procedure for something that is not one.
    #[test]
    fn a_pdu_that_is_not_one_of_the_three_alternatives_is_not_named() {
        assert_eq!(
            summarize("NGAP", &[0x60, 0x15, 0x00], procedure),
            "NGAP (unrecognised PDU)"
        );
        assert_eq!(
            summarize("NGAP", &[0xE0, 0x15, 0x00], procedure),
            "NGAP (unrecognised PDU)"
        );
    }
}
