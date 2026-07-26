// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Shared helpers for NGAP-family dissectors (NGAP, RANAP, S1AP, X2AP, etc.).

/// Kind of NGAP/RANAP message for procedure code lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    Initiating,
    SuccessfulOutcome,
    UnsuccessfulOutcome,
}

/// Build a human-readable summary for an AP (Application Protocol) PDU.
pub fn summarize(
    name: &str,
    _payload: &[u8],
    procedure_fn: fn(u8) -> Option<&'static str>,
) -> String {
    // Without actual ASN.1 PER decoding, try the first byte as a procedure code
    let code = _payload.first().copied().unwrap_or(0);
    match procedure_fn(code) {
        Some(desc) => format!("{name} {desc}"),
        None => format!("{name} procedure {code} [reject]"),
    }
}

#[cfg(test)]
pub mod test_helpers {
    use super::MessageKind;

    /// Build a minimal AP PDU for testing the dispatch path.
    pub fn ap_pdu(_kind: MessageKind, _procedure: u16) -> Vec<u8> {
        vec![]
    }
}
