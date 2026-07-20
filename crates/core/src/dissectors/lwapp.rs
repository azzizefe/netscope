// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// LWAPP control message types (RFC 5412 §7).
fn message_name(t: u8) -> Option<&'static str> {
    Some(match t {
        1 => "Discovery Request",
        2 => "Discovery Response",
        3 => "Join Request",
        4 => "Join Response",
        5 => "Join Ack",
        6 => "Join Confirm",
        10 => "Configure Request",
        11 => "Configure Response",
        12 => "Config Update Request",
        13 => "Config Update Response",
        14 => "WTP Event Request",
        15 => "WTP Event Response",
        16 => "Change State Event Request",
        17 => "Change State Event Response",
        18 => "Echo Request",
        19 => "Echo Response",
        20 => "Image Data Request",
        21 => "Image Data Response",
        22 => "Reset Request",
        23 => "Reset Response",
        24 => "Primary Discovery Request",
        25 => "Primary Discovery Response",
        26 => "Data Transfer Request",
        27 => "Data Transfer Response",
        28 => "Clear Config Indication",
        29 => "WLAN Config Request",
        30 => "WLAN Config Response",
        31 => "Mobile Config Request",
        32 => "Mobile Config Response",
        _ => return None,
    })
}

/// Flags, fragment id, length, status — then, on the control channel, the
/// control header.
const HEADER: usize = 6;
/// Set when the message carries a control header rather than user data.
const FLAG_CONTROL: u8 = 0x04;

/// Dissect an LWAPP message — how Cisco's thin access points are controlled by
/// a central wireless controller, on UDP 12222 (data) and 12223 (control)
/// (RFC 5412).
///
/// A thin access point has almost no intelligence of its own: it does not decide
/// which clients to admit or which channel to use, and it forwards its traffic
/// to a controller that makes those decisions for the whole site. LWAPP is that
/// leash. CAPWAP later standardised the same idea, so LWAPP mostly turns up in
/// older installations.
pub fn dissect_lwapp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < HEADER {
        format!("LWAPP ({})", super::bytes(payload.len() as u64))
    } else {
        let flags = payload[0];
        let length = u16::from_be_bytes([payload[2], payload[3]]);
        if flags & FLAG_CONTROL == 0 {
            // A data message carries an 802.11 frame rather than a command.
            format!("LWAPP data — {length} bytes of wireless traffic")
        } else {
            match payload.get(HEADER).copied().and_then(message_name) {
                Some(name) => format!("LWAPP {name}"),
                None => match payload.get(HEADER) {
                    Some(t) => format!("LWAPP control message {t}"),
                    None => "LWAPP control".to_string(),
                },
            }
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Lwapp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a control message of the given type.
    fn control(msg_type: u8) -> Vec<u8> {
        let mut p = vec![FLAG_CONTROL, 0x00];
        p.extend_from_slice(&16u16.to_be_bytes()); // length
        p.extend_from_slice(&0u16.to_be_bytes()); // status
        p.push(msg_type);
        p.extend_from_slice(&[0u8; 8]);
        p
    }

    #[test]
    fn join_sequence_is_legible() {
        let r = dissect_lwapp(None, None, 40000, 12223, &control(3));
        assert_eq!(r.protocol, Protocol::Lwapp);
        assert_eq!(r.summary, "LWAPP Join Request");
        assert_eq!(
            dissect_lwapp(None, None, 1, 12223, &control(4)).summary,
            "LWAPP Join Response"
        );
    }

    #[test]
    fn discovery_and_configuration_are_named() {
        assert_eq!(
            dissect_lwapp(None, None, 1, 12223, &control(1)).summary,
            "LWAPP Discovery Request"
        );
        assert_eq!(
            dissect_lwapp(None, None, 1, 12223, &control(29)).summary,
            "LWAPP WLAN Config Request"
        );
    }

    /// The control flag is what separates a command from a forwarded wireless
    /// frame; ignoring it would read client traffic as a control message.
    #[test]
    fn data_messages_are_distinguished_from_control() {
        let mut data = vec![0x00, 0x00];
        data.extend_from_slice(&1200u16.to_be_bytes());
        data.extend_from_slice(&[0u8; 8]);
        let r = dissect_lwapp(None, None, 1, 12222, &data);
        assert_eq!(r.summary, "LWAPP data — 1200 bytes of wireless traffic");
    }

    #[test]
    fn unknown_control_type_reports_its_number() {
        let r = dissect_lwapp(None, None, 1, 12223, &control(99));
        assert_eq!(r.summary, "LWAPP control message 99");
    }

    #[test]
    fn truncated_does_not_panic() {
        let r = dissect_lwapp(None, None, 1, 12223, &[0x04, 0x00]);
        assert_eq!(r.summary, "LWAPP (2 bytes)");
    }
}
