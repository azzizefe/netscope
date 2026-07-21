// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! openSAFETY — the frame that assumes the network is lying to it.
//!
//! A light curtain in front of a press, an emergency stop, a two-hand control:
//! these have to work when the network does not. openSAFETY solves that with
//! the *black channel* principle — the transport underneath is treated as
//! completely untrustworthy, and every safety guarantee is carried inside this
//! frame instead. The same frames ride over POWERLINK, PROFINET, EtherNet/IP or
//! Modbus without change, because none of them are trusted to do anything but
//! move bytes.
//!
//! ## What that makes worth reading
//!
//! * **SN_FAIL** — a safety node reporting a fault. Whatever it guards is about
//!   to be, or already is, in its safe state. This is the message that precedes
//!   a machine stopping, and it names an error group and code that say why.
//! * **SCM set to Stop** — the safety configuration manager taking nodes out of
//!   operation. Deliberate, but the reason is rarely written down anywhere else.
//! * **SN set to Operational** and the status replies — the handshake a node
//!   goes through before it is allowed to guard anything. A node cycling
//!   through this repeatedly never becomes operational, and the machine simply
//!   will not start with no obvious cause.
//! * **SPDO** — the actual safety process data. When these are flowing, the
//!   guard is live.
//!
//! ## Two fields that share bytes
//!
//! The 10-bit source address spans a byte boundary: the low eight bits are byte
//! 0, and the **top two bits live in the low two bits of byte 1**, which is
//! otherwise the message identifier. Reading byte 1 whole gives an unknown
//! message for every node above address 255; masking the address to one byte
//! makes four different nodes look like the same one.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Address, identifier, length, consecutive time, then data.
const HEADER: usize = 4;

/// Every node listens to this one.
const BROADCAST: u16 = 0x3FF;

/// The message identifier occupies the top six bits of byte 1.
fn message_name(id: u8) -> Option<&'static str> {
    Some(match id {
        0xC0 => "SPDO data",
        0xC8 => "SPDO data with time request",
        0xD0 => "SPDO data with time response",
        0xD8 => "SPDO reserved",
        0xE0 => "SSDO service request",
        0xE4 => "SSDO service response",
        0xE8 => "SSDO slim service request",
        0xEC => "SSDO slim service response",
        0xA0 => "SNMT request UDID",
        0xA4 => "SNMT response UDID",
        0xA8 => "SNMT assign address",
        0xAC => "SNMT address assigned",
        0xB0 => "SNMT service request",
        0xB4 => "SNMT service response",
        0xBC => "SNMT reset guarding",
        _ => return None,
    })
}

/// The SNMT extended services, in the first data byte. These are the ones that
/// move a node between states — and the one that reports a fault.
fn snmt_service(service: u8) -> Option<&'static str> {
    Some(match service {
        0x00 => "SN set to pre-operational",
        0x02 => "SN set to operational",
        0x04 => "SCM set to STOP",
        0x06 => "SCM set to operational",
        0x08 => "SCM guard SN",
        0x0A => "assign additional address",
        0x0C => "SN acknowledge",
        0x0E => "assign UDID to SCM",
        0x01 => "SN status: pre-operational",
        0x03 => "SN status: operational",
        0x05 => "additional address assigned",
        0x07 => "SN FAIL",
        0x09 => "SN busy",
        0x0F => "UDID assigned to SCM",
        0x10 => "assign initial consecutive time",
        0x11 => "initial consecutive time assigned",
        _ => return None,
    })
}

/// Whether an identifier belongs to the SNMT management family.
fn is_snmt(id: u8) -> bool {
    (0xA0..=0xBC).contains(&id)
}

/// Dissect an openSAFETY frame (UDP 9877, or 8755 over SERCOS III).
pub fn dissect_opensafety(
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
        protocol: Protocol::Opensafety,
        summary: describe(payload),
    }
}

pub(crate) fn describe(payload: &[u8]) -> String {
    let Some(head) = payload.get(..HEADER) else {
        return format!("openSAFETY ({})", super::bytes(payload.len() as u64));
    };

    // The address is ten bits: eight in byte 0, and the top two borrowed from
    // the low two bits of the identifier byte.
    let address = u16::from(head[0]) | (u16::from(head[1] & 0x03) << 8);
    let id = head[1] & 0xFC;

    let Some(name) = message_name(id) else {
        return format!("openSAFETY message {id:#04x} from {address:#05x}");
    };

    let node = if address == BROADCAST {
        "broadcast".to_string()
    } else {
        format!("node {address:#05x}")
    };

    // The consecutive time is what makes a stale or replayed frame detectable:
    // a receiver that sees the same count twice knows it is not fresh data.
    let count = head[3];

    // An SNMT frame's first data byte says which management service it is, and
    // that is where the interesting messages live.
    if is_snmt(id) {
        if let Some(&service) = payload.get(HEADER) {
            let described = snmt_service(service)
                .map(str::to_string)
                .unwrap_or_else(|| format!("service {service:#04x}"));

            // A failure names an error group and a code, which is the
            // difference between "a node faulted" and knowing which one.
            if service == 0x07 {
                let group = payload.get(HEADER + 1).copied().unwrap_or(0);
                let code = payload.get(HEADER + 2).copied().unwrap_or(0);
                let group = if group == 0 {
                    "device".to_string()
                } else {
                    format!("group {group}")
                };
                let code = if code == 0 {
                    "default".to_string()
                } else {
                    format!("vendor code {code}")
                };
                return format!("openSAFETY SN FAIL — {node} faulted ({group}, {code})");
            }
            return format!("openSAFETY {described} — {node}");
        }
    }

    format!("openSAFETY {name} from {node} (count {count})")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an openSAFETY frame.
    fn frame(address: u16, id: u8, count: u8, data: &[u8]) -> Vec<u8> {
        let mut v = vec![
            (address & 0xFF) as u8,
            id | ((address >> 8) & 0x03) as u8,
            data.len() as u8,
            count,
        ];
        v.extend_from_slice(data);
        v
    }

    /// The reason this dissector exists: this is the message that precedes a
    /// machine going to its safe state, and it says which node and why.
    #[test]
    fn a_node_failure_names_the_node_and_the_reason() {
        let r = dissect_opensafety(
            None,
            None,
            40000,
            9877,
            &frame(0x012, 0xB4, 5, &[0x07, 0x00, 0x00]),
        );
        assert_eq!(r.protocol, Protocol::Opensafety);
        assert_eq!(
            r.summary,
            "openSAFETY SN FAIL — node 0x012 faulted (device, default)"
        );
    }

    /// A vendor code is a different investigation from a device fault.
    #[test]
    fn a_failure_distinguishes_the_error_group_and_code() {
        let summary = describe(&frame(0x012, 0xB4, 5, &[0x07, 0x03, 0x2A]));
        assert!(summary.contains("group 3"), "{summary}");
        assert!(summary.contains("vendor code 42"), "{summary}");
    }

    /// The state machine a node walks before it may guard anything. A node
    /// cycling through it never becomes operational, and the machine will not
    /// start with nothing obviously wrong.
    #[test]
    fn the_state_transitions_are_named() {
        assert!(describe(&frame(1, 0xB0, 0, &[0x00])).contains("pre-operational"));
        assert!(describe(&frame(1, 0xB0, 0, &[0x02])).contains("set to operational"));
        assert!(describe(&frame(1, 0xB0, 0, &[0x04])).contains("SCM set to STOP"));
        assert!(describe(&frame(1, 0xB4, 0, &[0x09])).contains("SN busy"));
    }

    /// The address is ten bits spanning a byte boundary. Masking it to one
    /// byte makes four different nodes look like the same one.
    #[test]
    fn the_address_is_ten_bits_across_two_bytes() {
        let low = describe(&frame(0x012, 0xC0, 0, &[]));
        let high = describe(&frame(0x112, 0xC0, 0, &[]));
        assert!(low.contains("0x012"), "{low}");
        assert!(high.contains("0x112"), "{high}");
        assert_ne!(low, high, "the top bits must not be discarded");
    }

    /// Those same two bits sit inside the identifier byte. Reading it whole
    /// makes every node above address 255 an unknown message.
    #[test]
    fn the_identifier_excludes_the_address_bits() {
        for address in [0x000u16, 0x0FF, 0x100, 0x3FE] {
            let summary = describe(&frame(address, 0xC0, 0, &[]));
            assert!(summary.contains("SPDO data"), "{address:#05x}: {summary}");
        }
    }

    #[test]
    fn the_broadcast_address_is_named() {
        assert!(describe(&frame(BROADCAST, 0xC0, 0, &[])).contains("broadcast"));
    }

    /// Safety process data flowing means the guard is live.
    #[test]
    fn the_process_data_messages_are_named() {
        assert!(describe(&frame(1, 0xC0, 0, &[])).contains("SPDO data"));
        assert!(describe(&frame(1, 0xC8, 0, &[])).contains("time request"));
        assert!(describe(&frame(1, 0xD0, 0, &[])).contains("time response"));
    }

    /// The consecutive time is what makes a replayed frame detectable.
    #[test]
    fn the_consecutive_time_is_reported() {
        assert!(describe(&frame(1, 0xC0, 7, &[])).contains("count 7"));
        assert!(describe(&frame(1, 0xC0, 8, &[])).contains("count 8"));
    }

    #[test]
    fn an_unknown_message_reports_its_identifier() {
        assert!(describe(&frame(1, 0x40, 0, &[])).contains("message 0x40"));
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]), "openSAFETY (0 bytes)");
        assert_eq!(describe(&[0x01, 0xC0, 0x00]), "openSAFETY (3 bytes)");
        // An SNMT frame with no service byte falls back rather than guessing.
        assert_eq!(
            describe(&frame(1, 0xB0, 0, &[])),
            "openSAFETY SNMT service request from node 0x001 (count 0)"
        );
        // A failure with no group or code still names the node.
        assert!(describe(&frame(1, 0xB4, 0, &[0x07])).contains("faulted"));
    }
}
