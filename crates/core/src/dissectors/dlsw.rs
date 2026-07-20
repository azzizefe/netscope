// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// DLSw message types (RFC 1795 §3.3).
fn message_name(t: u8) -> Option<&'static str> {
    Some(match t {
        0x03 => "CANUREACH",
        0x04 => "ICANREACH",
        0x05 => "REACH_ACK",
        0x06 => "DGRMFRAME",
        0x07 => "XIDFRAME",
        0x08 => "CONTACT",
        0x09 => "CONTACTED",
        0x0A => "RESTART_DL",
        0x0B => "DL_RESTARTED",
        0x0C => "ENTER_BUSY",
        0x0D => "EXIT_BUSY",
        0x0E => "INFOFRAME",
        0x0F => "HALT_DL",
        0x10 => "DL_HALTED",
        0x11 => "NETBIOS_NQ",
        0x12 => "NETBIOS_NR",
        0x13 => "DATAFRAME",
        0x14 => "HALT_DL_NOACK",
        0x15 => "NETBIOS_ANQ",
        0x16 => "NETBIOS_ANR",
        0x17 => "KEEPALIVE",
        0x1E => "CAP_EXCHANGE",
        0x20 => "IFCM",
        0x21 => "TEST_CIRCUIT_REQ",
        0x22 => "TEST_CIRCUIT_RSP",
        _ => return None,
    })
}

/// Version 1 of the protocol, written as the ASCII digit.
const VERSION_1: u8 = 0x31;
/// The two header lengths RFC 1795 defines: control messages carry the full
/// header, information messages a shortened one.
const CONTROL_HEADER: u8 = 72;
const INFO_HEADER: u8 = 16;
/// Where the message type sits in either header.
const MESSAGE_TYPE_OFFSET: usize = 14;

/// Dissect a DLSw message — Data Link Switching, which carries IBM SNA and
/// NetBIOS traffic across an IP network, on TCP 2065 (RFC 1795).
///
/// SNA was designed for reliable leased lines and does not tolerate the delays
/// and loss of a routed network. DLSw solves that by terminating the SNA link
/// locally at each end and tunnelling between the two switches over TCP, so the
/// mainframe and the terminal each believe they are on a direct link.
pub fn dissect_dlsw(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary =
        parse(payload).unwrap_or_else(|| format!("DLSw ({})", super::bytes(payload.len() as u64)));
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Dlsw,
        summary,
    }
}

fn parse(payload: &[u8]) -> Option<String> {
    if *payload.first()? != VERSION_1 {
        return None;
    }
    // The header length distinguishes the two header formats and is a useful
    // sanity check: any other value means this is not a DLSw header.
    let header_len = *payload.get(1)?;
    if header_len != CONTROL_HEADER && header_len != INFO_HEADER {
        return None;
    }
    let msg_type = *payload.get(MESSAGE_TYPE_OFFSET)?;
    Some(match message_name(msg_type) {
        Some(name) => format!("DLSw {name}"),
        None => format!("DLSw message 0x{msg_type:02x}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a DLSw header of the given kind carrying `msg_type`.
    fn dlsw(header_len: u8, msg_type: u8) -> Vec<u8> {
        let mut p = vec![0u8; header_len as usize];
        p[0] = VERSION_1;
        p[1] = header_len;
        p[MESSAGE_TYPE_OFFSET] = msg_type;
        p
    }

    #[test]
    fn capability_exchange_is_named() {
        let r = dissect_dlsw(None, None, 40000, 2065, &dlsw(CONTROL_HEADER, 0x1E));
        assert_eq!(r.protocol, Protocol::Dlsw);
        assert_eq!(r.summary, "DLSw CAP_EXCHANGE");
    }

    /// The circuit-establishment exchange is what sets up a session between a
    /// terminal and a mainframe.
    #[test]
    fn circuit_setup_messages_are_named() {
        assert_eq!(
            dissect_dlsw(None, None, 1, 2065, &dlsw(CONTROL_HEADER, 0x03)).summary,
            "DLSw CANUREACH"
        );
        assert_eq!(
            dissect_dlsw(None, None, 1, 2065, &dlsw(CONTROL_HEADER, 0x04)).summary,
            "DLSw ICANREACH"
        );
        assert_eq!(
            dissect_dlsw(None, None, 1, 2065, &dlsw(CONTROL_HEADER, 0x08)).summary,
            "DLSw CONTACT"
        );
    }

    /// Information messages use the short header, and the message type sits at
    /// the same offset in both.
    #[test]
    fn short_header_messages_decode_too() {
        let r = dissect_dlsw(None, None, 1, 2065, &dlsw(INFO_HEADER, 0x0E));
        assert_eq!(r.summary, "DLSw INFOFRAME");
    }

    /// The version byte and the header length together are what identify DLSw;
    /// neither alone is distinctive enough.
    #[test]
    fn foreign_headers_are_not_claimed() {
        let mut wrong_version = dlsw(CONTROL_HEADER, 0x1E);
        wrong_version[0] = 0x47; // 'G', as HTTP would start
        assert!(parse(&wrong_version).is_none());

        let mut wrong_length = dlsw(CONTROL_HEADER, 0x1E);
        wrong_length[1] = 0x55;
        assert!(parse(&wrong_length).is_none());

        assert!(parse(&[]).is_none());
    }

    #[test]
    fn unknown_message_type_reports_its_byte() {
        let r = dissect_dlsw(None, None, 1, 2065, &dlsw(CONTROL_HEADER, 0x7E));
        assert_eq!(r.summary, "DLSw message 0x7e");
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_dlsw(None, None, 1, 2065, &[VERSION_1, CONTROL_HEADER, 0x00]);
        assert_eq!(r.summary, "DLSw (3 bytes)");
    }
}
