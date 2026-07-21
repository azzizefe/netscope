// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! NS over IP — the link that carries every cell's packet traffic.
//!
//! GPRS Network Service is the layer underneath [`super::bssgp`]: it multiplexes
//! many cells onto a set of virtual connections between the base station
//! subsystem and the SGSN, and keeps track of which of those connections are
//! alive.
//!
//! ## The heartbeat is the point
//!
//! `NS-ALIVE` and its acknowledgement run continuously on every virtual
//! connection. When the acknowledgements stop, the connection is declared dead
//! and every cell multiplexed onto it goes with it — which is why a handful of
//! missing acknowledgements is a much larger event than it looks. Subscribers
//! across several cells lose packet service at once, and the base station's own
//! logs show only that the link went down.
//!
//! `NS-BLOCK` is the orderly version of the same thing: a connection taken out
//! of service deliberately. Distinguishing the two matters because one is
//! maintenance and the other is a fault.
//!
//! ## Everything else is carried
//!
//! `NS-UNITDATA` is the envelope for real traffic. It names the cell in its own
//! header and hands the rest to BSSGP, so a capture that stops at this layer
//! sees only "data" where the interesting flow control and status messages are.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// PDU type, control bits, then the cell identifier.
const UNITDATA_HEADER: usize = 4;

const PDU_UNITDATA: u8 = 0x00;

fn pdu_name(pdu: u8) -> Option<&'static str> {
    Some(match pdu {
        PDU_UNITDATA => "data",
        0x02 => "RESET — a virtual connection is being rebuilt",
        0x03 => "reset ack",
        0x04 => "BLOCK — a virtual connection taken out of service",
        0x05 => "block ack",
        0x06 => "unblock",
        0x07 => "unblock ack",
        0x08 => "status",
        0x0A => "alive",
        0x0B => "alive ack",
        0x0C => "sub-network service ack",
        0x0D => "sub-network service add",
        0x0E => "sub-network service change weight",
        0x0F => "sub-network service config",
        0x10 => "sub-network service config ack",
        0x11 => "sub-network service delete",
        0x12 => "sub-network service size",
        0x13 => "sub-network service size ack",
        _ => return None,
    })
}

/// Dissect an NS-over-IP datagram (UDP 2157 or 19999 by convention).
pub fn dissect_nsip(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let (protocol, summary) = describe(payload);
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol,
        summary,
    }
}

fn describe(payload: &[u8]) -> (Protocol, String) {
    let Some(&pdu) = payload.first() else {
        return (Protocol::Nsip, "NS (0 bytes)".to_string());
    };
    let Some(name) = pdu_name(pdu) else {
        return (Protocol::Nsip, format!("NS PDU {pdu:#04x}"));
    };

    // Carried traffic is BSSGP, and that is where the diagnosis lives — so the
    // inner protocol is the answer and NS is the envelope.
    if pdu == PDU_UNITDATA {
        if let Some(head) = payload.get(..UNITDATA_HEADER) {
            let bvci = u16::from_be_bytes([head[2], head[3]]);
            if let Some(inner) = payload.get(UNITDATA_HEADER..) {
                if !inner.is_empty() {
                    return (
                        Protocol::Bssgp,
                        format!("NS cell {bvci} · {}", super::bssgp::describe(inner)),
                    );
                }
            }
            return (Protocol::Nsip, format!("NS data for cell {bvci}"));
        }
    }

    (Protocol::Nsip, format!("NS {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns(pdu: u8, bvci: u16, inner: &[u8]) -> Vec<u8> {
        let mut v = vec![pdu, 0x00];
        v.extend_from_slice(&bvci.to_be_bytes());
        v.extend_from_slice(inner);
        v
    }

    /// The reason this dissector exists: when the acknowledgements stop, every
    /// cell on the connection loses packet service at once.
    #[test]
    fn the_heartbeat_is_named() {
        let r = dissect_nsip(None, None, 2157, 2157, &[0x0A]);
        assert_eq!(r.protocol, Protocol::Nsip);
        assert_eq!(r.summary, "NS alive");
        assert_eq!(describe(&[0x0B]).1, "NS alive ack");
    }

    /// A deliberate block and a fault are different events.
    #[test]
    fn a_block_is_distinguished_from_a_reset() {
        assert!(describe(&[0x04]).1.contains("taken out of service"));
        assert!(describe(&[0x02]).1.contains("being rebuilt"));
    }

    /// Carried traffic is BSSGP, and stopping at this layer hides the flow
    /// control and status messages entirely.
    #[test]
    fn carried_traffic_is_handed_to_bssgp() {
        // A BSSGP status with an SGSN congestion cause.
        let inner = [0x41, 0x07, 0x81, 0x07];
        let (protocol, summary) = describe(&ns(PDU_UNITDATA, 42, &inner));
        assert_eq!(protocol, Protocol::Bssgp);
        assert!(summary.contains("cell 42"), "{summary}");
        assert!(summary.contains("SGSN congestion"), "{summary}");
    }

    /// The cell identifier is in the NS header, not the payload.
    #[test]
    fn the_cell_is_named_from_the_ns_header() {
        let (_, a) = describe(&ns(PDU_UNITDATA, 7, &[0x41]));
        let (_, b) = describe(&ns(PDU_UNITDATA, 9, &[0x41]));
        assert!(a.contains("cell 7"), "{a}");
        assert!(b.contains("cell 9"), "{b}");
    }

    /// Data with nothing after the header is not a BSSGP message.
    #[test]
    fn an_empty_unitdata_stays_ns() {
        let (protocol, summary) = describe(&ns(PDU_UNITDATA, 3, &[]));
        assert_eq!(protocol, Protocol::Nsip);
        assert_eq!(summary, "NS data for cell 3");
    }

    #[test]
    fn an_unknown_pdu_reports_its_number() {
        assert_eq!(describe(&[0x99]).1, "NS PDU 0x99");
    }

    #[test]
    fn truncated_does_not_panic() {
        assert_eq!(describe(&[]).1, "NS (0 bytes)");
        // A data PDU with no room for the cell identifier.
        assert_eq!(describe(&[PDU_UNITDATA, 0x00, 0x01]).1, "NS data");
    }
}
