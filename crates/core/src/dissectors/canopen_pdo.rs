// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! CANopen PDO — the process data itself.
//!
//! A PDO is the traffic a CANopen network exists to carry: the live values,
//! sent every cycle with no request and no acknowledgement. There is nothing to
//! decode inside one. The data field is whatever the object dictionary maps
//! into it, which differs per device and per configuration, so the bytes only
//! mean something to a reader who has the device's EDS file.
//!
//! What *is* knowable comes from the identifier: which PDO of the four, which
//! direction it travels, and which node it belongs to. [`super::canopen`]
//! decodes that from the COB-ID and passes it in — it is not in the payload,
//! and reading a byte of process data as though it were a type field turns a
//! real measurement into a made-up label.

use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a PDO whose identity the caller has already taken from the COB-ID.
///
/// `transmit` is the direction as CANopen names it, which is from the device's
/// point of view: a TPDO is the device reporting, an RPDO is the master
/// commanding.
#[allow(clippy::too_many_arguments)]
pub fn dissect_canopen_pdo(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    node: u8,
    number: u8,
    transmit: bool,
) -> DissectedResult {
    let kind = if transmit { "TPDO" } else { "RPDO" };
    let hex: Vec<String> = payload.iter().take(8).map(|b| format!("{b:02X}")).collect();
    let summary = if payload.is_empty() {
        format!("CANopen {kind}{number} — node {node}, no data")
    } else {
        format!(
            "CANopen {kind}{number} — node {node}, {} [{}]",
            super::bytes(payload.len() as u64),
            hex.join(" ")
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::CanopenPdo,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The direction and number come from the identifier, and both are what
    /// distinguish a device reporting from a master commanding.
    #[test]
    fn the_direction_and_number_come_from_the_caller() {
        let data = [0x01, 0x02, 0x03];
        let t = dissect_canopen_pdo(None, None, 0, 0, &data, 10, 1, true);
        assert_eq!(t.protocol, Protocol::CanopenPdo);
        assert_eq!(t.summary, "CANopen TPDO1 — node 10, 3 bytes [01 02 03]");

        let r = dissect_canopen_pdo(None, None, 0, 0, &data, 10, 2, false);
        assert_eq!(r.summary, "CANopen RPDO2 — node 10, 3 bytes [01 02 03]");
    }

    /// Every byte is process data — none of it is consumed as a header, so all
    /// of it is shown.
    #[test]
    fn the_whole_payload_is_data() {
        let full = [0xAA; 8];
        let r = dissect_canopen_pdo(None, None, 0, 0, &full, 3, 4, true);
        assert!(r.summary.contains("8 bytes"), "{}", r.summary);
        assert!(
            r.summary.contains("AA AA AA AA AA AA AA AA"),
            "{}",
            r.summary
        );
    }

    /// A PDO may legitimately carry nothing — a mapped length of zero is how a
    /// device says "nothing is mapped here".
    #[test]
    fn an_empty_pdo_is_not_malformed() {
        let r = dissect_canopen_pdo(None, None, 0, 0, &[], 7, 3, false);
        assert_eq!(r.summary, "CANopen RPDO3 — node 7, no data");
    }
}
