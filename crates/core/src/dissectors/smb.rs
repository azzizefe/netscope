// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! SMB — Windows file and printer sharing (MS-SMB2, MS-CIFS).
//!
//! SMB is the busiest protocol on most corporate networks, and knowing only
//! that a packet "is SMB" is close to useless. The command is what says whether
//! someone is opening a file, listing a directory, or failing to log in — and
//! the status code on a response is where failed authentication shows up, which
//! is why a run of `SESSION_SETUP` responses carrying a logon failure is worth
//! seeing at a glance.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// The two protocol markers. SMB1 is obsolete and disabled by default on modern
/// Windows, so seeing it at all is itself notable.
const SMB1_MAGIC: &[u8; 4] = b"\xFFSMB";
const SMB2_MAGIC: &[u8; 4] = b"\xFESMB";

/// Over TCP 445 a four-byte NetBIOS session header precedes the SMB header.
const SESSION_HEADER: usize = 4;

/// The SMB2 header is 64 bytes; the fields used here sit well inside that.
const SMB2_HEADER: usize = 64;
/// Set in the flags when the message is a response rather than a request.
const SMB2_FLAG_RESPONSE: u32 = 0x0000_0001;

/// SMB2 commands (MS-SMB2 §2.2.1.2).
fn smb2_command(cmd: u16) -> Option<&'static str> {
    Some(match cmd {
        0x0000 => "NEGOTIATE",
        0x0001 => "SESSION_SETUP",
        0x0002 => "LOGOFF",
        0x0003 => "TREE_CONNECT",
        0x0004 => "TREE_DISCONNECT",
        0x0005 => "CREATE (open a file)",
        0x0006 => "CLOSE",
        0x0007 => "FLUSH",
        0x0008 => "READ",
        0x0009 => "WRITE",
        0x000A => "LOCK",
        0x000B => "IOCTL",
        0x000C => "CANCEL",
        0x000D => "ECHO",
        0x000E => "QUERY_DIRECTORY",
        0x000F => "CHANGE_NOTIFY",
        0x0010 => "QUERY_INFO",
        0x0011 => "SET_INFO",
        0x0012 => "OPLOCK_BREAK",
        _ => return None,
    })
}

/// SMB1 commands worth naming (MS-CIFS §2.2.2.1).
fn smb1_command(cmd: u8) -> Option<&'static str> {
    Some(match cmd {
        0x00 => "CREATE_DIRECTORY",
        0x04 => "CLOSE",
        0x24 => "LOCKING_ANDX",
        0x25 => "TRANSACTION",
        0x2B => "ECHO",
        0x2E => "READ_ANDX",
        0x2F => "WRITE_ANDX",
        0x32 => "TRANS2",
        0x71 => "TREE_DISCONNECT",
        0x72 => "NEGOTIATE",
        0x73 => "SESSION_SETUP_ANDX",
        0x74 => "LOGOFF_ANDX",
        0x75 => "TREE_CONNECT_ANDX",
        0xA2 => "NT_CREATE_ANDX",
        _ => return None,
    })
}

/// NT status codes worth calling out. Success is the overwhelming majority, so
/// only the failures that mean something operationally are named.
fn status_name(status: u32) -> Option<&'static str> {
    Some(match status {
        0x0000_0000 => "success",
        0x0000_0103 => "pending",
        0x8000_0006 => "no more files",
        0xC000_0022 => "access denied",
        0xC000_0034 => "object name not found",
        0xC000_0035 => "object name collision",
        0xC000_003A => "object path not found",
        0xC000_006D => "logon failure",
        0xC000_006E => "account restriction",
        0xC000_006F => "invalid logon hours",
        0xC000_0070 => "invalid workstation",
        0xC000_0071 => "password expired",
        0xC000_0072 => "account disabled",
        0xC000_00CC => "bad network name",
        0xC000_0203 => "user session deleted",
        0xC000_0224 => "password must change",
        0xC000_0234 => "account locked out",
        _ => return None,
    })
}

/// Find the SMB header, skipping the NetBIOS session header when present.
fn smb_header(payload: &[u8]) -> Option<(&'static str, &[u8])> {
    for offset in [0, SESSION_HEADER] {
        let rest = payload.get(offset..)?;
        if rest.starts_with(SMB2_MAGIC) {
            return Some(("SMB2", rest));
        }
        if rest.starts_with(SMB1_MAGIC) {
            return Some(("SMB1", rest));
        }
    }
    None
}

/// Dissect an SMB segment (TCP 445).
pub fn dissect_smb(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = match smb_header(payload) {
        Some(("SMB2", header)) => smb2_summary(header),
        Some(("SMB1", header)) => smb1_summary(header),
        _ => format!("SMB ({})", super::bytes(payload.len() as u64)),
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Smb,
        summary,
    }
}

fn smb2_summary(header: &[u8]) -> String {
    if header.len() < SMB2_HEADER {
        return "SMB2 (truncated header)".to_string();
    }
    // Status, command and flags are all little-endian.
    let status = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
    let command = u16::from_le_bytes([header[12], header[13]]);
    let flags = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);
    let is_response = flags & SMB2_FLAG_RESPONSE != 0;

    let name = match smb2_command(command) {
        Some(n) => n.to_string(),
        None => format!("command 0x{command:04x}"),
    };
    if !is_response {
        return format!("SMB2 {name}");
    }
    // The status field only carries meaning on a response.
    match status_name(status) {
        Some("success") => format!("SMB2 {name} response"),
        Some(text) => format!("SMB2 {name} response — {text}"),
        None => format!("SMB2 {name} response — status 0x{status:08x}"),
    }
}

fn smb1_summary(header: &[u8]) -> String {
    let Some(&command) = header.get(4) else {
        return "SMB1 (truncated header)".to_string();
    };
    let name = match smb1_command(command) {
        Some(n) => n.to_string(),
        None => format!("command 0x{command:02x}"),
    };
    // SMB1 is disabled by default on current Windows, so its presence is worth
    // flagging rather than reporting neutrally.
    format!("SMB1 {name} (legacy protocol)")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an SMB2 message with a NetBIOS session header in front.
    fn smb2(command: u16, response: bool, status: u32) -> Vec<u8> {
        let mut p = vec![0x00, 0x00, 0x00, 0x40]; // NetBIOS session header
        p.extend_from_slice(SMB2_MAGIC);
        p.extend_from_slice(&64u16.to_le_bytes()); // structure size
        p.extend_from_slice(&0u16.to_le_bytes()); // credit charge
        p.extend_from_slice(&status.to_le_bytes());
        p.extend_from_slice(&command.to_le_bytes());
        p.extend_from_slice(&1u16.to_le_bytes()); // credits
        p.extend_from_slice(&(if response { 1u32 } else { 0 }).to_le_bytes());
        p.resize(SESSION_HEADER + SMB2_HEADER, 0);
        p
    }

    #[test]
    fn file_operations_are_named() {
        let r = dissect_smb(None, None, 50000, 445, &smb2(0x0005, false, 0));
        assert_eq!(r.protocol, Protocol::Smb);
        assert_eq!(r.summary, "SMB2 CREATE (open a file)");
        assert_eq!(
            dissect_smb(None, None, 1, 445, &smb2(0x0008, false, 0)).summary,
            "SMB2 READ"
        );
        assert_eq!(
            dissect_smb(None, None, 1, 445, &smb2(0x0009, false, 0)).summary,
            "SMB2 WRITE"
        );
    }

    /// A failed logon is the thing worth spotting in a pile of SMB traffic, and
    /// it only shows up in the status field of a response.
    #[test]
    fn failed_authentication_is_surfaced() {
        let r = dissect_smb(None, None, 445, 1, &smb2(0x0001, true, 0xC000_006D));
        assert_eq!(r.summary, "SMB2 SESSION_SETUP response — logon failure");
        let r = dissect_smb(None, None, 445, 1, &smb2(0x0001, true, 0xC000_0234));
        assert_eq!(
            r.summary,
            "SMB2 SESSION_SETUP response — account locked out"
        );
    }

    /// Other failures matter too: a missing share and a denied file read are
    /// different diagnoses.
    #[test]
    fn other_failures_are_named() {
        assert_eq!(
            dissect_smb(None, None, 445, 1, &smb2(0x0003, true, 0xC000_00CC)).summary,
            "SMB2 TREE_CONNECT response — bad network name"
        );
        assert_eq!(
            dissect_smb(None, None, 445, 1, &smb2(0x0005, true, 0xC000_0022)).summary,
            "SMB2 CREATE (open a file) response — access denied"
        );
    }

    /// The status field is only meaningful on a response; a request carries
    /// other data there and must not be read as a failure.
    #[test]
    fn request_status_field_is_not_reported() {
        let r = dissect_smb(None, None, 1, 445, &smb2(0x0005, false, 0xC000_006D));
        assert_eq!(r.summary, "SMB2 CREATE (open a file)");
    }

    #[test]
    fn successful_response_reads_cleanly() {
        let r = dissect_smb(None, None, 445, 1, &smb2(0x0008, true, 0));
        assert_eq!(r.summary, "SMB2 READ response");
    }

    /// SMB1 is disabled by default on current Windows, so seeing it is itself
    /// a finding worth flagging rather than reporting neutrally.
    #[test]
    fn smb1_is_flagged_as_legacy() {
        let mut p = vec![0x00, 0x00, 0x00, 0x20];
        p.extend_from_slice(SMB1_MAGIC);
        p.push(0x72); // NEGOTIATE
        p.resize(40, 0);
        let r = dissect_smb(None, None, 50000, 445, &p);
        assert_eq!(r.summary, "SMB1 NEGOTIATE (legacy protocol)");
    }

    /// Both framings appear: with the NetBIOS session header over port 445, and
    /// without it when the payload has already been unwrapped.
    #[test]
    fn header_is_found_with_or_without_the_session_prefix() {
        let with_prefix = smb2(0x0000, false, 0);
        let without = &with_prefix[SESSION_HEADER..];
        assert_eq!(
            dissect_smb(None, None, 1, 445, &with_prefix).summary,
            dissect_smb(None, None, 1, 445, without).summary
        );
    }

    #[test]
    fn unknown_command_reports_its_number() {
        let r = dissect_smb(None, None, 1, 445, &smb2(0x00FF, false, 0));
        assert_eq!(r.summary, "SMB2 command 0x00ff");
    }

    #[test]
    fn truncated_and_foreign_payloads_do_not_panic() {
        assert_eq!(
            dissect_smb(None, None, 1, 445, b"GET / HTTP/1.1").summary,
            "SMB (14 bytes)"
        );
        let mut short = vec![0x00, 0x00, 0x00, 0x40];
        short.extend_from_slice(SMB2_MAGIC);
        assert_eq!(
            dissect_smb(None, None, 1, 445, &short).summary,
            "SMB2 (truncated header)"
        );
        assert_eq!(
            dissect_smb(None, None, 1, 445, &[]).summary,
            "SMB (0 bytes)"
        );
    }
}
