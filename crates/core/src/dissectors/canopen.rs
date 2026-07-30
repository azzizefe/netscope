// SPDX-License-Identifier: LicenseRef-Proprietary
// Copyright (c) 2026 azzizefe. All rights reserved.
//! CANopen (CiA 301) — the identifier *is* the protocol.
//!
//! A CANopen frame carries no protocol field. The 11-bit identifier splits into
//! a 4-bit function code and a 7-bit node id, and the function code is the only
//! thing that says whether eight bytes are a configuration write, a process
//! value or a device announcing a fault:
//!
//! ```text
//!   10  9  8  7 | 6  5  4  3  2  1  0
//!  +------------+---------------------+
//!  | function   |       node id       |
//!  +------------+---------------------+
//! ```
//!
//! This is the "predefined connection set", and it is why the same eight bytes
//! mean different things at different identifiers.
//!
//! ## Why the payload is checked as well as the identifier
//!
//! Every 11-bit CAN bus uses identifiers in this range — a proprietary machine
//! bus will happily sit at 0x181 without being CANopen at all. Claiming the
//! range on its own would turn any such bus into imaginary CANopen traffic, the
//! same trap [`super::isotp`] documents. So each service also has to agree with
//! its own frame shape before it is claimed: NMT with a command specifier the
//! standard lists, SDO with a valid command byte and a full eight, heartbeat
//! with a single byte naming a real state.
//!
//! PDO is the weak one and is called out as such: its data field is whatever
//! the object dictionary maps there, so there is nothing to validate beyond the
//! length. It is claimed last and only when the node id is a real one.

use super::DissectedResult;

/// Node id occupies the low 7 bits; the function code is what remains.
const NODE_ID_MASK: u32 = 0x7F;

/// The services this module recognises, as named by the function code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Service {
    Nmt,
    Sync,
    Emergency,
    Time,
    /// Transmit PDO (device → master), numbered 1-4.
    TxPdo(u8),
    /// Receive PDO (master → device), numbered 1-4.
    RxPdo(u8),
    /// SDO server → client (the reply to a configuration access).
    SdoTx,
    /// SDO client → server (the configuration access itself).
    SdoRx,
    /// Heartbeat / node guarding — a device reporting that it is still alive.
    Heartbeat,
}

/// Classify an identifier, or `None` if it falls in a band CiA 301 reserves.
fn service_of(id: u32) -> Option<Service> {
    let node = id & NODE_ID_MASK;
    match id >> 7 {
        // Node control is a broadcast: it addresses its target in the payload,
        // not in the identifier, so only node id 0 is a real NMT frame.
        0x0 if node == 0 => Some(Service::Nmt),
        0x1 if node == 0 => Some(Service::Sync),
        0x1 => Some(Service::Emergency),
        0x2 if node == 0 => Some(Service::Time),
        0x3 => Some(Service::TxPdo(1)),
        0x4 => Some(Service::RxPdo(1)),
        0x5 => Some(Service::TxPdo(2)),
        0x6 => Some(Service::RxPdo(2)),
        0x7 => Some(Service::TxPdo(3)),
        0x8 => Some(Service::RxPdo(3)),
        0x9 => Some(Service::TxPdo(4)),
        0xA => Some(Service::RxPdo(4)),
        0xB => Some(Service::SdoTx),
        0xC => Some(Service::SdoRx),
        0xE => Some(Service::Heartbeat),
        _ => None,
    }
}

/// Whether this frame is CANopen: the identifier names a service, and the
/// payload agrees with what that service looks like.
///
/// Only standard (11-bit) identifiers are considered — CANopen's predefined
/// connection set is an 11-bit assignment, and a 29-bit bus using the same
/// numbers is a different network.
pub(crate) fn owns(id: u32, extended: bool, payload: &[u8]) -> bool {
    if extended {
        return false;
    }
    let node = id & NODE_ID_MASK;
    match service_of(id) {
        // Command specifier plus the node it addresses. The specifiers are the
        // five CiA 301 defines; anything else is not a node-control frame.
        Some(Service::Nmt) => payload.len() == 2 && matches!(payload[0], 1 | 2 | 128 | 129 | 130),
        // SYNC is empty, or carries a single counter byte.
        Some(Service::Sync) => payload.len() <= 1,
        // TIME is a six-byte TIME_OF_DAY.
        Some(Service::Time) => payload.len() == 6,
        // The emergency object is a fixed eight bytes.
        Some(Service::Emergency) => payload.len() == 8 && node != 0,
        // An SDO is always eight bytes, and the top three bits of the command
        // byte are the command specifier — 0-4 are the defined ones for each
        // direction, 5-7 are block transfer.
        Some(Service::SdoTx) | Some(Service::SdoRx) => payload.len() == 8 && node != 0,
        // One byte, and it names a state: boot-up, stopped, operational or
        // pre-operational. Nothing else is a valid heartbeat.
        Some(Service::Heartbeat) => {
            payload.len() == 1 && matches!(payload[0] & 0x7F, 0 | 4 | 5 | 127) && node != 0
        }
        // Nothing in a PDO is checkable — the data field is whatever the object
        // dictionary maps into it. The identifier and a plausible length are
        // all there is, so this is the weakest claim in the module.
        Some(Service::TxPdo(_)) | Some(Service::RxPdo(_)) => {
            node != 0 && !payload.is_empty() && payload.len() <= 8
        }
        None => false,
    }
}

/// Dissect a frame [`owns`] has already accepted.
pub(crate) fn result(id: u32, payload: &[u8]) -> DissectedResult {
    let node = (id & NODE_ID_MASK) as u8;
    match service_of(id) {
        Some(Service::Nmt) => super::canopen_nmt::dissect_canopen_nmt(None, None, 0, 0, payload),
        Some(Service::SdoTx) => {
            super::canopen_sdo::dissect_canopen_sdo(None, None, 0, 0, payload, node, true)
        }
        Some(Service::SdoRx) => {
            super::canopen_sdo::dissect_canopen_sdo(None, None, 0, 0, payload, node, false)
        }
        Some(Service::TxPdo(n)) => {
            super::canopen_pdo::dissect_canopen_pdo(None, None, 0, 0, payload, node, n, true)
        }
        Some(Service::RxPdo(n)) => {
            super::canopen_pdo::dissect_canopen_pdo(None, None, 0, 0, payload, node, n, false)
        }
        Some(Service::Heartbeat) => heartbeat(node, payload),
        Some(Service::Sync) => simple(format!(
            "CANopen SYNC{}",
            match payload.first() {
                Some(c) => format!(" (counter {c})"),
                None => String::new(),
            }
        )),
        Some(Service::Time) => simple("CANopen TIME".to_string()),
        Some(Service::Emergency) => emergency(node, payload),
        None => simple("CANopen".to_string()),
    }
}

fn simple(summary: String) -> DissectedResult {
    DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: crate::models::Protocol::Canopen,
        summary,
    }
}

/// The state a device reports it is in. A node that keeps re-announcing
/// `boot-up` is a node that keeps restarting.
fn heartbeat(node: u8, payload: &[u8]) -> DissectedResult {
    let state = match payload[0] & 0x7F {
        0 => "boot-up",
        4 => "stopped",
        5 => "operational",
        127 => "pre-operational",
        _ => "unknown state",
    };
    simple(format!("CANopen heartbeat — node {node} {state}"))
}

/// The emergency object: an error code, the error register, and five bytes of
/// manufacturer-specific detail. The code is the part worth reading.
fn emergency(node: u8, payload: &[u8]) -> DissectedResult {
    let code = u16::from_le_bytes([payload[0], payload[1]]);
    // The error class is the top nibble of the code; the rest narrows it down
    // to a specific fault the device defines.
    let what = match code & 0xF000 {
        0x0000 => "error reset / no error",
        0x1000 => "generic error",
        0x2000 => "current",
        0x3000 => "voltage",
        0x4000 => "temperature",
        0x5000 => "device hardware",
        0x6000 => "device software",
        0x7000 => "additional modules",
        0x8000 => "monitoring",
        0x9000 => "external error",
        0xF000 => "additional functions",
        _ => "device specific",
    };
    simple(format!(
        "CANopen EMCY — node {node} code 0x{code:04X} ({what}), register 0x{:02X}",
        payload[2]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reason this module exists: the same eight bytes mean different
    /// things at different identifiers, and only the identifier says which.
    #[test]
    fn the_identifier_selects_the_service() {
        let eight = [0x40, 0x00, 0x10, 0x00, 0, 0, 0, 0];
        // 0x601 is an SDO from the client, 0x581 the server's reply.
        assert!(result(0x601, &eight).summary.starts_with("CANopen SDO"));
        assert!(result(0x581, &eight).summary.starts_with("CANopen SDO"));
        // The same bytes at a PDO identifier are process data, not a request.
        assert!(result(0x181, &eight).summary.contains("TPDO1"));
    }

    /// A heartbeat is one byte naming a state, and a node stuck in boot-up is
    /// a node that keeps restarting.
    #[test]
    fn a_heartbeat_names_the_state_and_the_node() {
        assert!(owns(0x70A, false, &[0x05]));
        assert_eq!(
            result(0x70A, &[0x05]).summary,
            "CANopen heartbeat — node 10 operational"
        );
        assert_eq!(
            result(0x70A, &[0x00]).summary,
            "CANopen heartbeat — node 10 boot-up"
        );
    }

    /// The emergency object is where a device says what went wrong.
    #[test]
    fn an_emergency_reports_its_error_class() {
        let emcy = [0x30, 0x43, 0x01, 0, 0, 0, 0, 0];
        assert!(owns(0x087, false, &emcy));
        let s = result(0x087, &emcy).summary;
        assert!(s.contains("node 7"), "{s}");
        assert!(s.contains("0x4330"), "{s}");
        assert!(s.contains("temperature"), "{s}");
    }

    /// The guard is what stops a proprietary 11-bit bus becoming imaginary
    /// CANopen — each service has to agree with its own frame shape.
    #[test]
    fn a_frame_that_does_not_fit_its_service_is_not_claimed() {
        // NMT is exactly two bytes with a listed command specifier.
        assert!(owns(0x000, false, &[0x01, 0x0A]));
        assert!(!owns(0x000, false, &[0x99, 0x0A]));
        assert!(!owns(0x000, false, &[0x01]));
        // An SDO is exactly eight bytes.
        assert!(!owns(0x601, false, &[0x40, 0x00, 0x10]));
        // A heartbeat byte has to name a real state.
        assert!(!owns(0x70A, false, &[0x42]));
        // Reserved bands are never claimed.
        assert!(!owns(0x7DF, false, &[0u8; 8]));
        assert!(!owns(0x680, false, &[0u8; 8]));
        // And a 29-bit bus using the same numbers is a different network.
        assert!(!owns(0x601, true, &[0u8; 8]));
    }

    /// Node id 0 is a broadcast, and only the services that are broadcasts may
    /// use it — an SDO or heartbeat addressed to nobody is not CANopen.
    #[test]
    fn node_zero_is_only_valid_where_it_means_broadcast() {
        assert!(owns(0x080, false, &[]));
        assert!(!owns(0x580, false, &[0u8; 8]));
        assert!(!owns(0x700, false, &[0x05]));
    }
}
