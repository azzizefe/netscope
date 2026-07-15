// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a BACnet/IP message (UDP 47808 / 0xBAC0).
///
/// BACnet runs building automation — HVAC, lighting, access control. Over IP it
/// is wrapped in BVLC: type(1, always 0x81 for BACnet/IP), function(1),
/// length(2, big endian). The NPDU and APDU follow. The APDU's first nibble is
/// the PDU type (confirmed/unconfirmed request, ack…); for unconfirmed requests
/// the service choice names the operation — Who-Is / I-Am being the classic
/// discovery pair. We surface the BVLC function and the APDU service.
pub fn dissect_bacnet(
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
        protocol: Protocol::Bacnet,
        summary,
    };

    if payload.len() < 4 || payload[0] != 0x81 {
        return result("BACnet/IP (partial)".into());
    }

    let bvlc_func = payload[1];
    // NPDU begins after the 4-byte BVLC header. NPDU: version(1), control(1),
    // then optional routing fields we skip past when the control bit says so.
    let npdu = &payload[4..];
    if let Some(service) = apdu_service(npdu) {
        return result(format!("BACnet {service}"));
    }

    result(format!("BACnet/IP {}", bvlc_function(bvlc_func)))
}

fn bvlc_function(f: u8) -> &'static str {
    match f {
        0x00 => "BVLC-Result",
        0x04 => "Forwarded-NPDU",
        0x05 => "Register-Foreign-Device",
        0x0a => "Original-Unicast-NPDU",
        0x0b => "Original-Broadcast-NPDU",
        _ => "message",
    }
}

/// Peek the APDU service out of an NPDU. Only handles the common
/// no-routing case (control byte without the destination-present bit).
fn apdu_service(npdu: &[u8]) -> Option<&'static str> {
    if npdu.len() < 2 {
        return None;
    }
    let control = npdu[1];
    // Bit 5 (0x20) = destination present adds address fields we don't parse;
    // bail to the generic label rather than mis-index.
    if control & 0x20 != 0 {
        return None;
    }
    let apdu = &npdu[2..];
    if apdu.is_empty() {
        return None;
    }
    let pdu_type = apdu[0] >> 4;
    match pdu_type {
        0x1 => {
            // Unconfirmed request: [type][service choice]
            let choice = apdu.get(1).copied()?;
            Some(unconfirmed_service(choice))
        }
        0x0 => {
            // Confirmed request: [type][max-segs/resp][invoke-id][service]
            let choice = apdu.get(3).copied()?;
            Some(confirmed_service(choice))
        }
        _ => None,
    }
}

fn unconfirmed_service(choice: u8) -> &'static str {
    match choice {
        0 => "I-Am",
        1 => "I-Have",
        2 => "Unconfirmed-COV-Notification",
        3 => "Unconfirmed-Event-Notification",
        4 => "Unconfirmed-Private-Transfer",
        5 => "Unconfirmed-Text-Message",
        6 => "Time-Synchronization",
        7 => "Who-Has",
        8 => "Who-Is",
        _ => "Unconfirmed-Request",
    }
}

fn confirmed_service(choice: u8) -> &'static str {
    match choice {
        12 => "ReadProperty",
        14 => "ReadPropertyMultiple",
        15 => "WriteProperty",
        16 => "WritePropertyMultiple",
        _ => "Confirmed-Request",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn who_is_broadcast() {
        // BVLC 0x81 / Original-Broadcast-NPDU / len, then NPDU version+control,
        // then APDU: unconfirmed request (0x10) + service Who-Is (8).
        let payload = [0x81, 0x0b, 0x00, 0x0c, 0x01, 0x00, 0x10, 0x08];
        let r = dissect_bacnet(None, None, 47808, 47808, &payload);
        assert_eq!(r.protocol, Protocol::Bacnet);
        assert_eq!(r.summary, "BACnet Who-Is");
    }

    #[test]
    fn i_am_reply() {
        let payload = [0x81, 0x0b, 0x00, 0x0c, 0x01, 0x00, 0x10, 0x00];
        let r = dissect_bacnet(None, None, 47808, 47808, &payload);
        assert_eq!(r.summary, "BACnet I-Am");
    }

    #[test]
    fn partial_is_safe() {
        let r = dissect_bacnet(None, None, 47808, 47808, &[0x81]);
        assert!(r.summary.contains("partial"));
    }
}
