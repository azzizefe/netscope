// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! MLE — Mesh Link Establishment, how Thread devices form and maintain a mesh
//! (Thread specification, based on draft-kelsey-intarea-mesh-link-establishment).
//!
//! A Thread network has no fixed topology: devices arrive, find a parent, take
//! on a role and leave again as batteries die or people move things. MLE is the
//! conversation that runs all of that — a child asking for a parent, routers
//! advertising themselves, a device announcing it is leaving.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The first byte is a security suite selector. Thread uses either 802.15.4
/// security or none; anything else is not MLE.
const SECURITY_ENABLED: u8 = 0;
const SECURITY_NONE: u8 = 255;

/// MLE command types (Thread specification §4.4).
fn command_name(cmd: u8) -> Option<&'static str> {
    Some(match cmd {
        0 => "Link Request",
        1 => "Link Accept",
        2 => "Link Accept and Request",
        3 => "Link Reject",
        4 => "Advertisement",
        5 => "Update",
        6 => "Update Request",
        7 => "Data Request",
        8 => "Data Response",
        9 => "Parent Request",
        10 => "Parent Response",
        11 => "Child ID Request",
        12 => "Child ID Response",
        13 => "Child Update Request",
        14 => "Child Update Response",
        15 => "Announce",
        16 => "Discovery Request",
        17 => "Discovery Response",
        _ => return None,
    })
}

/// Dissect an MLE message (UDP 19788).
pub fn dissect_mle(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let result = |summary: String| DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Mle,
        summary,
    };

    let Some(&suite) = payload.first() else {
        return result("MLE (empty)".into());
    };
    match suite {
        // Without security the command byte follows immediately.
        SECURITY_NONE => match payload.get(1).copied().and_then(command_name) {
            Some(name) => result(format!("MLE {name} (unsecured)")),
            None => result(format!(
                "MLE ({}, unsecured)",
                super::bytes(payload.len() as u64)
            )),
        },
        // With security an auxiliary header of variable length sits in between,
        // and the command itself is inside the encrypted portion — so there is
        // nothing further to read without the network key.
        SECURITY_ENABLED => result(format!(
            "MLE encrypted ({})",
            super::bytes(payload.len() as u64)
        )),
        other => result(format!("MLE (unknown security suite {other})")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unsecured(cmd: u8) -> Vec<u8> {
        vec![SECURITY_NONE, cmd, 0x00, 0x00]
    }

    #[test]
    fn parent_request_is_named() {
        let r = dissect_mle(None, None, 19788, 19788, &unsecured(9));
        assert_eq!(r.protocol, Protocol::Mle);
        assert_eq!(r.summary, "MLE Parent Request (unsecured)");
    }

    /// Joining a mesh is a specific sequence, and each step should be legible.
    #[test]
    fn the_join_sequence_is_legible() {
        assert_eq!(
            dissect_mle(None, None, 1, 19788, &unsecured(10)).summary,
            "MLE Parent Response (unsecured)"
        );
        assert_eq!(
            dissect_mle(None, None, 1, 19788, &unsecured(11)).summary,
            "MLE Child ID Request (unsecured)"
        );
        assert_eq!(
            dissect_mle(None, None, 1, 19788, &unsecured(12)).summary,
            "MLE Child ID Response (unsecured)"
        );
    }

    /// Most real traffic is secured, and the command is inside the encrypted
    /// part — saying so is more honest than guessing at an offset.
    #[test]
    fn secured_messages_report_that_they_are_encrypted() {
        let r = dissect_mle(None, None, 1, 19788, &[SECURITY_ENABLED, 0x15, 0x00, 0x00]);
        assert_eq!(r.summary, "MLE encrypted (4 bytes)");
    }

    #[test]
    fn unknown_security_suite_is_reported() {
        let r = dissect_mle(None, None, 1, 19788, &[7, 0x09]);
        assert_eq!(r.summary, "MLE (unknown security suite 7)");
    }

    #[test]
    fn unknown_command_reports_the_size() {
        let r = dissect_mle(None, None, 1, 19788, &unsecured(99));
        assert_eq!(r.summary, "MLE (4 bytes, unsecured)");
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(
            dissect_mle(None, None, 1, 19788, &[SECURITY_NONE]).summary,
            "MLE (1 byte, unsecured)"
        );
        assert_eq!(
            dissect_mle(None, None, 1, 19788, &[]).summary,
            "MLE (empty)"
        );
    }
}
