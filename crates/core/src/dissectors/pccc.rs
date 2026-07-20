// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! PCCC — the older Allen-Bradley command set, tunnelled inside CIP.
//!
//! Rockwell's newer controllers speak CIP natively, but the installed base of
//! PLC-5 and SLC-500 hardware speaks PCCC, and CIP carries it verbatim through
//! an "Execute PCCC" service. So a modern EtherNet/IP capture on a plant floor
//! frequently contains a decades-old command set two layers down, and it is the
//! PCCC function — not the CIP service wrapping it — that says whether a
//! controller is being read or written.

/// The PCCC header carried inside CIP: a requestor-id length byte, then that
/// many bytes of requestor id, then command, status and transaction.
const MIN_HEADER: usize = 4;

/// PCCC commands paired with their function code (Allen-Bradley 1770-6.5.16).
/// Command 0x0F is the extended form where the function byte selects the
/// operation; the others are complete on their own.
fn function_name(cmd: u8, fnc: u8) -> Option<&'static str> {
    Some(match (cmd, fnc) {
        (0x0F, 0x00) => "Word Range Write",
        (0x0F, 0x01) => "Word Range Read",
        (0x0F, 0x02) => "Bit Write",
        (0x0F, 0x03) => "Read Modify Write",
        (0x0F, 0x11) => "Change Mode",
        (0x0F, 0x17) => "Read Bytes Physical",
        (0x0F, 0x18) => "Write Bytes Physical",
        (0x0F, 0x26) => "Read Modify Write N",
        (0x0F, 0x29) => "Read Section Size",
        (0x0F, 0x3A) => "Set CPU Mode",
        (0x0F, 0x41) => "Set Variables",
        (0x0F, 0x50) => "Shutdown",
        (0x0F, 0x52) => "Upload All Request",
        (0x0F, 0x53) => "Upload Complete",
        (0x0F, 0x57) => "Download All Request",
        (0x0F, 0x5E) => "Download Complete",
        (0x0F, 0x67) => "Typed Write",
        (0x0F, 0x68) => "Typed Read",
        (0x0F, 0x79) => "Read Link Parameters",
        (0x0F, 0x80) => "Change Processor Mode",
        (0x0F, 0xA1) => "Protected Typed Logical Read (2 address fields)",
        (0x0F, 0xA2) => "Protected Typed Logical Read (3 address fields)",
        (0x0F, 0xA9) => "Protected Typed Logical Write (2 address fields)",
        (0x0F, 0xAA) => "Protected Typed Logical Write (3 address fields)",
        (0x0F, 0xAB) => "Protected Typed Logical Write with Mask",
        (0x06, 0x00) => "Echo",
        (0x06, 0x03) => "Diagnostic Status",
        (0x06, 0x04) => "Diagnostic Counters Reset",
        (0x06, 0x07) => "Set ENQs",
        (0x06, 0x09) => "Set NAKs",
        _ => return None,
    })
}

/// Status codes worth naming (1770-6.5.16 §7.3).
fn status_name(status: u8) -> Option<&'static str> {
    Some(match status {
        0x00 => "success",
        0x10 => "illegal command or format",
        0x20 => "host has a problem",
        0x30 => "remote node missing or off-line",
        0x40 => "host could not complete the request",
        0x50 => "addressing problem or memory protect rungs",
        0x60 => "function disallowed",
        0x70 => "processor is in Program mode",
        0x80 => "compatibility mode file missing",
        0x90 => "remote node cannot buffer the command",
        0xB0 => "remote node problem due to download",
        0xF0 => "error in the EXT STS byte",
        _ => return None,
    })
}

/// Describe a PCCC message, or `None` if it does not look like one.
///
/// Returned rather than a `DissectedResult` so CIP can decide whether the more
/// specific PCCC label applies to the packet.
pub(crate) fn describe(payload: &[u8]) -> Option<String> {
    // The requestor id is variable-length and its length byte comes first.
    let requestor_len = *payload.first()? as usize;
    // A length of zero, or one that runs past the buffer, means this is not a
    // PCCC header — CIP hands us whatever it found, so the check matters.
    if requestor_len < MIN_HEADER {
        return None;
    }
    let body = payload.get(requestor_len..)?;

    let cmd = *body.first()?;
    let status = *body.get(1)?;
    // A two-byte transaction number sits between the status and the function.
    let fnc = *body.get(4)?;

    // The response bit is the high bit of the command byte.
    let is_response = cmd & 0x40 != 0;
    let base_cmd = cmd & !0x40;

    if is_response {
        return Some(match status_name(status) {
            Some("success") => "PCCC response".to_string(),
            Some(text) => format!("PCCC response — {text}"),
            None => format!("PCCC response — status 0x{status:02x}"),
        });
    }
    Some(match function_name(base_cmd, fnc) {
        Some(name) => format!("PCCC {name}"),
        None => format!("PCCC command 0x{base_cmd:02x}/0x{fnc:02x}"),
    })
}

// This module has no `dissect_*` entry point of its own.
//
// Its parent builds the result, because the parent is what knows the context
// the summary needs — the session handle, the point codes, the subsystem
// numbers. A second entry point here would be a code path nothing calls, free
// to drift out of step with the one that runs.

#[cfg(test)]
pub(crate) mod test_helpers {
    /// Build a PCCC message: a 7-byte requestor id (length, CIP vendor, CIP
    /// serial), then command, status, transaction and function.
    pub fn pccc(cmd: u8, fnc: u8, status: u8) -> Vec<u8> {
        let mut p = vec![0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01];
        p.push(cmd);
        p.push(status);
        p.extend_from_slice(&[0x01, 0x00]); // transaction
        p.push(fnc);
        p
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::pccc;
    use super::*;

    #[test]
    fn protected_typed_logical_read_is_named() {
        let p = pccc(0x0F, 0xA2, 0x00);
        assert_eq!(
            describe(&p).as_deref(),
            Some("PCCC Protected Typed Logical Read (3 address fields)")
        );
    }

    /// The writes and the mode changes are what alter a running machine.
    #[test]
    fn writes_and_mode_changes_are_named() {
        assert_eq!(
            describe(&pccc(0x0F, 0xAA, 0x00)).as_deref(),
            Some("PCCC Protected Typed Logical Write (3 address fields)")
        );
        assert_eq!(
            describe(&pccc(0x0F, 0x80, 0x00)).as_deref(),
            Some("PCCC Change Processor Mode")
        );
        assert_eq!(
            describe(&pccc(0x0F, 0x50, 0x00)).as_deref(),
            Some("PCCC Shutdown")
        );
    }

    /// The response bit shares the command byte; leaving it in would fail to
    /// match any function name.
    #[test]
    fn response_bit_is_masked_and_status_named() {
        assert_eq!(
            describe(&pccc(0x4F, 0xA2, 0x00)).as_deref(),
            Some("PCCC response")
        );
        assert_eq!(
            describe(&pccc(0x4F, 0xA2, 0x70)).as_deref(),
            Some("PCCC response — processor is in Program mode")
        );
        assert_eq!(
            describe(&pccc(0x4F, 0xA2, 0x60)).as_deref(),
            Some("PCCC response — function disallowed")
        );
    }

    #[test]
    fn unknown_function_reports_both_bytes() {
        assert_eq!(
            describe(&pccc(0x0F, 0x7E, 0x00)).as_deref(),
            Some("PCCC command 0x0f/0x7e")
        );
    }

    /// The requestor-id length is what frames the rest; a nonsense value means
    /// CIP handed us something that is not PCCC.
    #[test]
    fn implausible_requestor_length_is_not_claimed() {
        assert_eq!(describe(&[0x00, 0x0F, 0x00]), None);
        assert_eq!(describe(&[0x02, 0x0F, 0x00]), None);
        assert_eq!(describe(&[0xFF, 0x0F, 0x00]), None);
        assert_eq!(describe(&[]), None);
    }

    #[test]
    fn truncated_body_is_not_claimed() {
        assert_eq!(describe(&[0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01]), None);
    }

    /// Unrecognised bytes must yield nothing, which is how CIP learns the
    /// tunnel was not carrying PCCC after all.
    #[test]
    fn unrecognised_bytes_are_not_described() {
        assert!(describe(&pccc(0x0F, 0xA2, 0x00)).is_some());
        assert!(describe(&[0xFF]).is_none());
    }
}
