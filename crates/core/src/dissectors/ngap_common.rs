// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! Shared helpers for NGAP-family dissectors (NGAP, RANAP, S1AP, X2AP, etc.).

use std::net::IpAddr;
use crate::models::Protocol;

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
    procedure: Option<u16>,
) -> String {
    match procedure {
        Some(code) => format!("{name} procedure 0x{code:04X}"),
        None => format!("{name} PDU"),
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
