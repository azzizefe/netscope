// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! kpasswd — changing a Kerberos password, or an administrator resetting one.
//!
//! Two different operations share this port, and the difference matters. A
//! *change* is a user replacing their own password, having proved they know the
//! old one. A *set* is an administrator overwriting somebody else's without
//! knowing it — the same wire protocol, a different version number, and a very
//! different thing to see in a capture.
//!
//! # What this cannot tell you
//!
//! Whether it worked. The result code lives inside the KRB-PRIV structure,
//! which is encrypted with the session key, so a capture shows that a password
//! operation happened and against which realm — not whether it was accepted or
//! refused for policy. Claiming otherwise would need a key netscope does not
//! have, so the summary stops where the encryption does.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// A user changing their own password (RFC 3244).
const VERSION_CHANGE: u16 = 0x0001;
/// An administrator setting someone else's (Microsoft's extension, also in
/// RFC 3244). The version number is the only thing that distinguishes them.
const VERSION_SET: u16 = 0xFF80;

/// Dissect a kpasswd message (UDP/TCP 464).
pub fn dissect_kpasswd(
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
        protocol: Protocol::Kpasswd,
        summary: describe(payload),
    }
}

fn describe(payload: &[u8]) -> String {
    // Message length, then the version.
    let Some(version) = payload.get(2..4).map(|b| u16::from_be_bytes([b[0], b[1]])) else {
        return "kpasswd".to_string();
    };

    let what = match version {
        VERSION_CHANGE => "password change",
        VERSION_SET => "password set (an administrator overwriting an account's password)",
        other => return format!("kpasswd (version 0x{other:04x})"),
    };

    // The ticket length is zero on a reply, which is how the two directions are
    // told apart without needing to know which side the capture was taken on.
    let ticket_len = payload
        .get(4..6)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .unwrap_or(0);
    if ticket_len == 0 {
        format!("kpasswd {what} — reply")
    } else {
        format!("kpasswd {what} — request")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a kpasswd message.
    fn message(version: u16, ticket_len: u16) -> Vec<u8> {
        let mut p = vec![0x00, 0x40];
        p.extend_from_slice(&version.to_be_bytes());
        p.extend_from_slice(&ticket_len.to_be_bytes());
        p.extend_from_slice(&[0u8; 32]);
        p
    }

    /// A user changing their own password: the routine case.
    #[test]
    fn a_change_is_named_as_one() {
        let r = dissect_kpasswd(None, None, 50000, 464, &message(VERSION_CHANGE, 100));
        assert_eq!(r.protocol, Protocol::Kpasswd);
        assert_eq!(r.summary, "kpasswd password change — request");
    }

    /// An administrator overwriting someone else's password without knowing it
    /// is a different operation, and only the version number says so.
    #[test]
    fn a_set_is_distinguished_from_a_change() {
        let summary = dissect_kpasswd(None, None, 50000, 464, &message(VERSION_SET, 100)).summary;
        assert!(summary.contains("administrator overwriting"), "{summary}");
        assert!(!summary.contains("password change —"), "{summary}");
    }

    /// A reply carries no ticket, which is how the direction is read without
    /// assuming which end the capture came from.
    #[test]
    fn a_reply_is_distinguished_by_its_empty_ticket() {
        assert!(
            dissect_kpasswd(None, None, 464, 50000, &message(VERSION_CHANGE, 0))
                .summary
                .ends_with("reply")
        );
        assert!(
            dissect_kpasswd(None, None, 50000, 464, &message(VERSION_CHANGE, 90))
                .summary
                .ends_with("request")
        );
    }

    /// A version outside the two defined ones keeps its number rather than
    /// being assumed to be one of them.
    #[test]
    fn an_unknown_version_keeps_its_number() {
        assert_eq!(
            dissect_kpasswd(None, None, 1, 464, &message(0x0042, 10)).summary,
            "kpasswd (version 0x0042)"
        );
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "kpasswd");
        assert_eq!(describe(&[0x00, 0x40]), "kpasswd");
        assert!(describe(&[0x00, 0x40, 0x00, 0x01]).contains("password change"));
    }
}
