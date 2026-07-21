// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! CN/IP (ANSI/CEA-852) — LonWorks building control carried over IP.
//!
//! A large building's HVAC, lighting and access control often still run on
//! LonWorks, a control network older than the IP infrastructure around it. CN/IP
//! is how those segments are joined across a campus: each router registers with
//! a configuration server, joins a channel, and tunnels its native
//! [`super::lontalk`] frames to the others.
//!
//! ## Why the membership traffic is worth reading
//!
//! Once a channel is established, everything should be `Data Packet`. The
//! configuration messages — `Device Registration`, `Channel Membership`, `Send
//! List` — belong to a channel that is forming. Seeing them repeatedly means
//! routers keep dropping out and re-registering, and while that happens control
//! messages between segments are being lost. The symptom in the building is a
//! zone whose setpoint occasionally does not take effect, which is nearly
//! impossible to trace from inside the control software.
//!
//! ## Two things the header says that nothing else will
//!
//! * **The security flag.** CN/IP can authenticate its packets. A channel
//!   configured for authentication carrying unauthenticated packets is a
//!   misconfigured router, and every device on it is one that anyone with
//!   access to the network can command.
//! * **The urgent channel.** Port 1629 is the priority path and 1628 the
//!   ordinary one. Time-critical control uses the former; a device that has
//!   been configured onto the wrong one has latency nobody can explain from
//!   the application.
//!
//! The sequence number and session identifier are what distinguish a router
//! that is retransmitting from one that has restarted — a restart resets the
//! session, a retransmission does not.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Length, version, type, extension length, flags, vendor, session, sequence,
/// timestamp.
const HEADER: usize = 20;

/// The packet that carries control traffic; everything else is channel setup.
const DATA_PACKET: u8 = 0x01;

/// The protocol code that means the payload is a native LonTalk frame.
const PCODE_LONTALK: u8 = 0;

fn packet_type(kind: u8) -> Option<&'static str> {
    Some(match kind {
        0x01 => "data",
        0x03 => "device registration",
        0x63 => "device configuration request",
        0x71 => "device configuration",
        0x04 => "channel membership",
        0x64 => "channel membership request",
        0x06 => "send list",
        0x66 => "send list request",
        0x08 => "channel routing",
        0x68 => "channel routing request",
        0x07 => "acknowledge",
        0x7F => "segment",
        0x60 => "status request",
        0x70 => "status response",
        _ => return None,
    })
}

/// Dissect a CN/IP packet (UDP 1628 normal, 1629 urgent).
pub fn dissect_cnip(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    // The urgent channel is a different port, not a header field.
    let urgent = src_port == 1629 || dst_port == 1629;
    let (protocol, summary) = describe(payload, urgent);
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol,
        summary,
    }
}

fn describe(payload: &[u8], urgent: bool) -> (Protocol, String) {
    let Some(head) = payload.get(..HEADER) else {
        return (
            Protocol::Cnip,
            format!("CN/IP ({})", super::bytes(payload.len() as u64)),
        );
    };
    let kind = head[3];
    // The extension length counts four-byte units, not bytes. Treating it as
    // bytes leaves the inner frame misaligned by three quarters of its offset.
    let extensions = head[4] as usize * 4;
    let secured = head[5] & 0x20 != 0;
    let pcode = head[5] & 0x1F;
    let session = u32::from_be_bytes([head[8], head[9], head[10], head[11]]);

    let priority = if urgent { "urgent" } else { "normal" };

    // A data packet carrying LonTalk is the control traffic itself, so the
    // inner protocol is the answer and CN/IP is the envelope.
    if kind == DATA_PACKET && pcode == PCODE_LONTALK {
        if let Some(inner) = payload.get(HEADER + extensions..) {
            if !inner.is_empty() {
                let mut summary = super::lontalk::describe(inner);
                if secured {
                    summary.push_str(" [authenticated]");
                }
                return (Protocol::Lontalk, format!("CN/IP {priority} · {summary}"));
            }
        }
    }

    let name = packet_type(kind)
        .map(str::to_string)
        .unwrap_or_else(|| format!("type {kind:#04x}"));

    let security = if secured { ", authenticated" } else { "" };
    (
        Protocol::Cnip,
        format!("CN/IP {name} ({priority}, session {session}{security})"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a CN/IP packet.
    fn cnip(kind: u8, pcode: u8, secured: bool, extensions: u8, inner: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&(HEADER as u16).to_be_bytes()); // length
        v.push(0x01); // version
        v.push(kind);
        v.push(extensions);
        v.push(if secured { 0x20 | pcode } else { pcode });
        v.extend_from_slice(&0u16.to_be_bytes()); // vendor code
        v.extend_from_slice(&99u32.to_be_bytes()); // session
        v.extend_from_slice(&1u32.to_be_bytes()); // sequence
        v.extend_from_slice(&0u32.to_be_bytes()); // timestamp
        v.extend_from_slice(&vec![0u8; extensions as usize * 4]);
        v.extend_from_slice(inner);
        v
    }

    /// A LonTalk acknowledged message, as the inner frame.
    fn lon() -> Vec<u8> {
        vec![0x00, 0x10, 0x01, 0x02, 0x03, 0x00]
    }

    /// The reason this dissector exists: once a channel is up everything
    /// should be data, so configuration traffic means routers are re-forming.
    #[test]
    fn channel_setup_is_distinguished_from_data() {
        let (protocol, summary) = describe(&cnip(0x03, 0, false, 0, &[]), false);
        assert_eq!(protocol, Protocol::Cnip);
        assert!(summary.contains("device registration"), "{summary}");

        let (protocol, _) = describe(&cnip(DATA_PACKET, PCODE_LONTALK, false, 0, &lon()), false);
        assert_eq!(protocol, Protocol::Lontalk, "data is the inner protocol");
    }

    /// An unauthenticated packet on a channel configured for authentication is
    /// a router anyone on the network can command.
    #[test]
    fn the_security_flag_is_reported() {
        let (_, secured) = describe(&cnip(0x03, 0, true, 0, &[]), false);
        let (_, plain) = describe(&cnip(0x03, 0, false, 0, &[]), false);
        assert!(secured.contains("authenticated"), "{secured}");
        assert!(!plain.contains("authenticated"), "{plain}");
    }

    /// The urgent channel is a port, not a header field.
    #[test]
    fn the_urgent_channel_comes_from_the_port() {
        let packet = cnip(0x03, 0, false, 0, &[]);
        let urgent = dissect_cnip(None, None, 40000, 1629, &packet);
        let normal = dissect_cnip(None, None, 40000, 1628, &packet);
        assert!(urgent.summary.contains("urgent"), "{}", urgent.summary);
        assert!(normal.summary.contains("normal"), "{}", normal.summary);
    }

    /// The extension length counts four-byte units. Treating it as a byte
    /// count starts the inner frame three quarters of the way too early, so
    /// the LonTalk header is read out of the extension padding.
    #[test]
    fn the_extension_length_counts_four_byte_units() {
        let with = cnip(DATA_PACKET, PCODE_LONTALK, false, 2, &lon());
        let without = cnip(DATA_PACKET, PCODE_LONTALK, false, 0, &lon());
        let (_, a) = describe(&with, false);
        let (_, b) = describe(&without, false);
        assert_eq!(a, b, "the extensions must be skipped, not read");
    }

    /// A session identifier separates a router that restarted from one that is
    /// merely retransmitting.
    #[test]
    fn the_session_is_reported() {
        let (_, summary) = describe(&cnip(0x03, 0, false, 0, &[]), false);
        assert!(summary.contains("session 99"), "{summary}");
    }

    #[test]
    fn the_configuration_types_are_named() {
        for (kind, name) in [
            (0x04u8, "channel membership"),
            (0x06, "send list"),
            (0x08, "channel routing"),
            (0x70, "status response"),
        ] {
            let (_, summary) = describe(&cnip(kind, 0, false, 0, &[]), false);
            assert!(summary.contains(name), "{kind:#04x}: {summary}");
        }
    }

    #[test]
    fn an_unknown_type_reports_its_number() {
        let (_, summary) = describe(&cnip(0x55, 0, false, 0, &[]), false);
        assert!(summary.contains("type 0x55"), "{summary}");
    }

    /// A data packet with no payload after the header is not a LonTalk frame.
    #[test]
    fn an_empty_data_packet_stays_cnip() {
        let (protocol, _) = describe(&cnip(DATA_PACKET, PCODE_LONTALK, false, 0, &[]), false);
        assert_eq!(protocol, Protocol::Cnip);
    }

    #[test]
    fn truncated_does_not_panic() {
        let (protocol, summary) = describe(&[], false);
        assert_eq!(protocol, Protocol::Cnip);
        assert_eq!(summary, "CN/IP (0 bytes)");
        assert_eq!(describe(&[0u8; 19], false).1, "CN/IP (19 bytes)");
        // Extensions that claim more than the packet holds leave nothing to
        // hand on, so it stays CN/IP rather than reading past the end.
        let mut short = cnip(DATA_PACKET, PCODE_LONTALK, false, 40, &lon());
        short.truncate(HEADER + 8);
        let (protocol, _) = describe(&short, false);
        assert_eq!(protocol, Protocol::Cnip);
    }
}
