// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Shared helpers for 3GPP RAN Application Part (RANAP, RNSAP, NBAP, S1AP,
//! NGAP, etc.) dissectors.
//!
//! Every RANAP-family protocol carries the same ASN.1 PER wrapper (procedure
//! code, criticality, message kind) around a protocol-specific body. This
//! module extracts that wrapper and hands back a label, so each dissector only
//! needs to supply its own procedure-code table.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The message kind signalled inside the ASN.1 PER wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    InitiatingMessage,
    SuccessfulOutcome,
    UnsuccessfulOutcome,
    Outcome,
}

/// Produce a summary for a RANAP-family PDU.
///
/// `name` is the protocol name shown in the summary (e.g. "S1AP").
/// `payload` is the full PDU starting from the ASN.1 PER CHOICE tag.
/// `procedure` maps a procedure code to a human label.
pub fn summarize(
    name: &str,
    payload: &[u8],
    procedure: fn(u8) -> Option<&'static str>,
) -> String {
    if payload.is_empty() {
        return format!("{name} — empty PDU");
    }
    // ASN.1 PER CHOICE index is the first byte. Message kind is encoded in
    // the top bits; an exact decode needs the full PER stack, but most
    // RANAP-family messages use a single-byte tag.
    let tag = payload[0];
    let (kind, approx_code) = if tag & 0x80 == 0 {
        (MessageKind::InitiatingMessage, tag & 0x7F)
    } else if tag & 0x40 == 0 {
        (MessageKind::SuccessfulOutcome, tag & 0x3F)
    } else {
        (MessageKind::UnsuccessfulOutcome, tag & 0x3F)
    };
    let label = procedure(approx_code).unwrap_or("unknown procedure");
    let kind_str = match kind {
        MessageKind::InitiatingMessage => "request",
        MessageKind::SuccessfulOutcome => "success",
        MessageKind::UnsuccessfulOutcome | MessageKind::Outcome => "failure",
    };
    format!("{name} {label} ({kind_str})")
}

#[cfg(test)]
pub mod test_helpers {
    /// Build a minimal AP PDU for testing.
    pub fn ap_pdu(procedure_code: u8, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(procedure_code); // CHOICE tag
        v.push(0x00);           // criticality + length placeholder
        v.extend_from_slice(body);
        v
    }
}
