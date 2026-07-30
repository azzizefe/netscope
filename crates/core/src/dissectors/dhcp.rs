// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::{IpAddr, Ipv4Addr};

use crate::models::Protocol;

use super::DissectedResult;

/// The BOOTP fixed header is 236 bytes; DHCP appends a 4-byte magic cookie
/// (0x63825363) followed by a TLV option list.
const BOOTP_FIXED_LEN: usize = 236;
const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

/// Dissect a DHCP / BOOTP message (UDP 67/68). Reports the DHCP message type
/// (Discover / Offer / Request / ACK / …) and, for Offer/ACK, the offered
/// address (`yiaddr`).
pub fn dissect_dhcp(
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
        protocol: Protocol::Dhcp,
        summary,
    };

    if payload.len() < BOOTP_FIXED_LEN {
        return result("DHCP (truncated)".into());
    }

    // yiaddr — "your" (client) address the server is assigning — is at offset 16.
    let yiaddr = Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);

    // Options begin after the magic cookie, if present.
    let options = if payload.len() >= BOOTP_FIXED_LEN + 4
        && payload[BOOTP_FIXED_LEN..BOOTP_FIXED_LEN + 4] == MAGIC_COOKIE
    {
        Some(&payload[BOOTP_FIXED_LEN + 4..])
    } else {
        None
    };
    let msg_type = options
        .and_then(|o| find_option(o, OPTION_MESSAGE_TYPE))
        .and_then(|v| v.first().copied());

    let summary = match msg_type {
        Some(t) => {
            let name = dhcp_type_name(t);
            // Offer (2) and ACK (5) carry the assigned address.
            let base = if (t == 2 || t == 5) && !yiaddr.is_unspecified() {
                format!("DHCP {name} — {yiaddr}")
            } else {
                format!("DHCP {name}")
            };
            // A relay agent adds the port the request physically arrived on.
            // That is the one fact in DHCP that a MAC address cannot give you:
            // it says where a device is plugged in, not just what it claims to
            // be — which is how an unexpected lease gets traced to a socket.
            match options.and_then(relay_agent) {
                Some(where_from) => format!("{base} · via {where_from}"),
                None => base,
            }
        }
        None => match payload[0] {
            1 => "DHCP/BOOTP Request".into(),
            2 => "DHCP/BOOTP Reply".into(),
            _ => "DHCP/BOOTP message".into(),
        },
    };

    result(summary)
}

/// Option 53 carries the message type.
const OPTION_MESSAGE_TYPE: u8 = 53;
/// Option 82 is what a relay agent adds on the way past.
const OPTION_RELAY_AGENT: u8 = 82;
/// Within option 82: which port, and which relay.
const SUBOPTION_CIRCUIT_ID: u8 = 1;
const SUBOPTION_REMOTE_ID: u8 = 2;

/// Find an option's value in the TLV list.
///
/// Options are `tag, len, value…`; tag 0 is padding and tag 255 (End)
/// terminates the list.
fn find_option(mut opts: &[u8], wanted: u8) -> Option<&[u8]> {
    while let Some((&tag, rest)) = opts.split_first() {
        match tag {
            0 => opts = rest, // Pad
            255 => break,     // End
            _ => {
                let len = *rest.first()? as usize;
                let value = rest.get(1..1 + len)?;
                if tag == wanted {
                    return Some(value);
                }
                opts = &rest[1 + len..];
            }
        }
    }
    None
}

/// Where a relayed request physically came from, from option 82.
///
/// The circuit id identifies the port and the remote id the relay itself.
/// Neither has a fixed encoding — switch vendors put a readable string in one
/// and packed binary in the other — so each is shown as text when it is text
/// and as hex when it is not, rather than being forced into either.
fn relay_agent(opts: &[u8]) -> Option<String> {
    let value = find_option(opts, OPTION_RELAY_AGENT)?;
    let mut circuit = None;
    let mut remote = None;

    let mut rest = value;
    while let Some((&tag, tail)) = rest.split_first() {
        let len = *tail.first()? as usize;
        let sub = tail.get(1..1 + len)?;
        match tag {
            SUBOPTION_CIRCUIT_ID => circuit = Some(readable(sub)),
            SUBOPTION_REMOTE_ID => remote = Some(readable(sub)),
            _ => {}
        }
        rest = tail.get(1 + len..)?;
    }

    match (circuit, remote) {
        (Some(c), Some(r)) => Some(format!("{c} on {r}")),
        (Some(c), None) => Some(c),
        (None, Some(r)) => Some(r),
        (None, None) => None,
    }
}

/// Render an identifier as text when it is text, and as hex when it is not.
fn readable(bytes: &[u8]) -> String {
    let printable = !bytes.is_empty()
        && bytes
            .iter()
            .all(|&b| b.is_ascii_graphic() || b == b' ' || b == b'/');
    if printable {
        String::from_utf8_lossy(bytes).into_owned()
    } else {
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

fn dhcp_type_name(t: u8) -> &'static str {
    match t {
        1 => "Discover",
        2 => "Offer",
        3 => "Request",
        4 => "Decline",
        5 => "ACK",
        6 => "NAK",
        7 => "Release",
        8 => "Inform",
        _ => "message",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DHCP packet: BOOTP header + cookie + option 53.
    fn dhcp_packet(op: u8, yiaddr: [u8; 4], msg_type: Option<u8>) -> Vec<u8> {
        let mut p = vec![0u8; BOOTP_FIXED_LEN];
        p[0] = op;
        p[16..20].copy_from_slice(&yiaddr);
        if let Some(t) = msg_type {
            p.extend_from_slice(&MAGIC_COOKIE);
            p.extend_from_slice(&[53, 1, t]); // option 53, len 1, value
            p.push(255); // End
        }
        p
    }

    #[test]
    fn discover_is_labeled() {
        let pkt = dhcp_packet(1, [0, 0, 0, 0], Some(1));
        let r = dissect_dhcp(None, None, 68, 67, &pkt);
        assert_eq!(r.protocol, Protocol::Dhcp);
        assert_eq!(r.summary, "DHCP Discover");
    }

    #[test]
    fn offer_includes_assigned_address() {
        let pkt = dhcp_packet(2, [192, 168, 1, 50], Some(2));
        let r = dissect_dhcp(None, None, 67, 68, &pkt);
        assert_eq!(r.summary, "DHCP Offer — 192.168.1.50");
    }

    #[test]
    fn ack_includes_assigned_address() {
        let pkt = dhcp_packet(2, [10, 0, 0, 7], Some(5));
        let r = dissect_dhcp(None, None, 67, 68, &pkt);
        assert_eq!(r.summary, "DHCP ACK — 10.0.0.7");
    }

    #[test]
    fn bootp_without_options_falls_back_to_op() {
        let pkt = dhcp_packet(1, [0, 0, 0, 0], None);
        let r = dissect_dhcp(None, None, 68, 67, &pkt);
        assert_eq!(r.summary, "DHCP/BOOTP Request");
    }

    #[test]
    fn truncated_is_handled() {
        let r = dissect_dhcp(None, None, 68, 67, &[0u8; 10]);
        assert_eq!(r.protocol, Protocol::Dhcp);
        assert!(r.summary.contains("truncated"));
    }

    /// A request carrying option 82 with the given sub-options.
    fn relayed(msg_type: u8, subs: &[(u8, &[u8])]) -> Vec<u8> {
        let mut agent = Vec::new();
        for (tag, value) in subs {
            agent.push(*tag);
            agent.push(value.len() as u8);
            agent.extend_from_slice(value);
        }
        let mut p = vec![0u8; BOOTP_FIXED_LEN];
        p[0] = 1;
        p.extend_from_slice(&MAGIC_COOKIE);
        p.extend_from_slice(&[53, 1, msg_type]);
        p.push(OPTION_RELAY_AGENT);
        p.push(agent.len() as u8);
        p.extend_from_slice(&agent);
        p.push(255);
        p
    }

    /// The one fact a MAC address cannot give you: where the device is
    /// physically plugged in.
    #[test]
    fn a_relayed_request_says_which_port_it_came_from() {
        let p = relayed(1, &[(SUBOPTION_CIRCUIT_ID, b"Gi1/0/24")]);
        let r = dissect_dhcp(None, None, 67, 67, &p);
        assert_eq!(r.protocol, Protocol::Dhcp);
        assert_eq!(r.summary, "DHCP Discover · via Gi1/0/24");
    }

    /// Both identifiers together say which port on which switch, which is what
    /// makes the answer unambiguous on a network with many relays.
    #[test]
    fn the_port_and_the_relay_are_both_reported() {
        let p = relayed(
            1,
            &[
                (SUBOPTION_CIRCUIT_ID, b"Gi1/0/24"),
                (SUBOPTION_REMOTE_ID, b"switch-3"),
            ],
        );
        assert_eq!(
            dissect_dhcp(None, None, 67, 67, &p).summary,
            "DHCP Discover · via Gi1/0/24 on switch-3"
        );
    }

    /// Vendors disagree on the encoding: some write a readable port name, some
    /// pack VLAN and port into binary. Forcing either into the other's shape
    /// produces mojibake or an unreadable number, so the two are handled apart.
    #[test]
    fn binary_identifiers_are_shown_as_hex_not_mangled_text() {
        // Cisco-style: type, length, VLAN, module, port.
        let p = relayed(
            1,
            &[(SUBOPTION_CIRCUIT_ID, &[0x00, 0x04, 0x00, 0x01, 0x00, 0x18])],
        );
        let summary = dissect_dhcp(None, None, 67, 67, &p).summary;
        assert_eq!(summary, "DHCP Discover · via 00:04:00:01:00:18");
        assert!(!summary.contains('\u{fffd}'), "mangled binary into text");

        // A relay id that is a MAC address is also binary.
        let p = relayed(
            1,
            &[(SUBOPTION_REMOTE_ID, &[0xAA, 0xBB, 0xCC, 0x00, 0x11, 0x22])],
        );
        assert!(dissect_dhcp(None, None, 67, 67, &p)
            .summary
            .contains("aa:bb:cc:00:11:22"));
    }

    /// A lease reply is relayed back the same way, and the port matters just as
    /// much there.
    #[test]
    fn a_reply_carries_the_relay_information_too() {
        let mut p = relayed(5, &[(SUBOPTION_CIRCUIT_ID, b"eth0.100")]);
        p[16..20].copy_from_slice(&[192, 168, 1, 50]);
        assert_eq!(
            dissect_dhcp(None, None, 67, 68, &p).summary,
            "DHCP ACK — 192.168.1.50 · via eth0.100"
        );
    }

    /// An unrelayed request is the common case and must not gain a trailing
    /// "via" with nothing after it.
    #[test]
    fn an_unrelayed_request_is_unchanged() {
        let r = dissect_dhcp(None, None, 68, 67, &dhcp_packet(1, [0, 0, 0, 0], Some(1)));
        assert_eq!(r.summary, "DHCP Discover");
    }

    /// Option 82 with only sub-options this does not read must not produce an
    /// empty fragment, and a malformed one must not panic.
    #[test]
    fn unreadable_relay_information_is_omitted_rather_than_left_empty() {
        let p = relayed(1, &[(9, b"vendor-specific")]);
        assert_eq!(
            dissect_dhcp(None, None, 67, 67, &p).summary,
            "DHCP Discover"
        );

        // A sub-option whose length runs past the end of the option.
        let mut p = vec![0u8; BOOTP_FIXED_LEN];
        p[0] = 1;
        p.extend_from_slice(&MAGIC_COOKIE);
        p.extend_from_slice(&[53, 1, 1]);
        p.extend_from_slice(&[OPTION_RELAY_AGENT, 3, SUBOPTION_CIRCUIT_ID, 200, 0x41]);
        p.push(255);
        let r = dissect_dhcp(None, None, 67, 67, &p);
        assert_eq!(r.summary, "DHCP Discover");
    }
}
