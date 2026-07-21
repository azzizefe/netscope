// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! CAN bus dissector — SocketCAN captures (`LINKTYPE_CAN_SOCKETCAN`, DLT 227).
//!
//! Linux exposes CAN controllers (`can0`, `vcan0`, `slcan0`) as ordinary
//! capture interfaces, so netscope reads vehicle/industrial bus traffic with
//! the same live path as Ethernet. Each frame carries an 8-byte pseudo-header:
//!
//! ```text
//! +---------------+------+----------+----------+  ID field is big-endian and
//! | CAN ID + flags| len  | FD flags | reserved |  carries EFF/RTR/ERR bits in
//! |    4 bytes    |  1   |    1     |    2     |  the top three positions.
//! +---------------+------+----------+----------+
//! ```

use super::DissectedResult;
use crate::models::Protocol;

/// Flag bits in the CAN ID field.
const CAN_EFF_FLAG: u32 = 0x8000_0000; // extended (29-bit) frame format
const CAN_RTR_FLAG: u32 = 0x4000_0000; // remote transmission request
const CAN_ERR_FLAG: u32 = 0x2000_0000; // error message frame
const CAN_EFF_MASK: u32 = 0x1FFF_FFFF;
const CAN_SFF_MASK: u32 = 0x0000_07FF;

/// Flag bits in the CAN FD flags byte (SocketCAN's `canfd_frame.flags`).
const CAN_FD_BRS: u8 = 0x01; // data phase sent at the higher bit rate
const CAN_FD_ESI: u8 = 0x02; // the transmitting node is error-passive

pub fn dissect_can(data: &[u8]) -> DissectedResult {
    let base = DissectedResult {
        src_addr: None,
        dst_addr: None,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Can,
        summary: String::new(),
    };
    if data.len() < 8 {
        return DissectedResult {
            protocol: Protocol::Unknown("truncated CAN frame".into()),
            summary: "Malformed CAN frame (shorter than the 8-byte header)".into(),
            ..base
        };
    }

    let raw_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let extended = raw_id & CAN_EFF_FLAG != 0;
    let rtr = raw_id & CAN_RTR_FLAG != 0;
    let error = raw_id & CAN_ERR_FLAG != 0;
    let id = raw_id & if extended { CAN_EFF_MASK } else { CAN_SFF_MASK };
    let len = data[4] as usize;
    let fd_flags = data[5];
    let payload = &data[8..data.len().min(8 + len)];
    // Classic CAN tops out at 8 data bytes; a longer frame (or explicit FD
    // flags) means CAN FD.
    let fd = len > 8 || fd_flags != 0;

    let mut parts: Vec<String> = Vec::new();
    if error {
        parts.push("error frame".into());
    }
    if rtr {
        parts.push("remote request".into());
    }
    if extended {
        parts.push("ext".into());
    }
    if fd {
        // The FD flags are not decoration. ESI means the transmitting node has
        // entered its error-passive state — it is still on the bus but already
        // degrading, and it will go bus-off if the fault continues. That is a
        // failing controller announcing itself one step before it disappears.
        let mut fd_notes = vec!["FD"];
        if fd_flags & CAN_FD_BRS != 0 {
            fd_notes.push("bit-rate switched");
        }
        if fd_flags & CAN_FD_ESI != 0 {
            fd_notes.push("SENDER ERROR-PASSIVE");
        }
        parts.push(fd_notes.join(", "));
    }
    let notes = if parts.is_empty() {
        String::new()
    } else {
        format!(" ({})", parts.join(", "))
    };

    let hex: Vec<String> = payload
        .iter()
        .take(16)
        .map(|b| format!("{b:02X}"))
        .collect();
    let ellipsis = if payload.len() > 16 { " …" } else { "" };
    let data_part = if rtr {
        String::new()
    } else {
        format!("  {}{}", hex.join(" "), ellipsis)
    };

    // An identifier is not an opaque number. A 29-bit one whose parameter group
    // the J1939 standard defines, or an 11-bit one in the range OBD-II owns,
    // says what the frame is about — which beats a line of hex.
    //
    // Neither is claimed on shape alone: J1939 needs a group number the
    // standard actually lists, and OBD-II's identifiers are reserved by it. A
    // proprietary bus using extended identifiers stays a plain CAN frame.
    if !rtr && !error {
        if extended && super::j1939::looks_like_j1939(id) {
            return super::j1939::result(id, payload);
        }
        if !extended && super::obd2::owns_id(id) {
            return super::obd2::result(id, payload);
        }
        // DeviceNet uses standard (11-bit) identifiers. The identifier range is
        // the guard — four message groups with distinct ID bands (§2 of the
        // DeviceNet spec). This check comes after OBD-II because OBD-II's
        // identifiers (0x7E0-0x7EF, 0x7DF) overlap with DeviceNet group 4.
        if !extended && super::devicenet::looks_like_devicenet(id) {
            return super::devicenet::result(id, payload);
        }
        // Diagnostics ride ISO-TP, which is what carries a UDS message too long
        // for one frame. It is claimed on the *identifier* first: ISO-TP has no
        // magic and its frame type is four bits, so one payload in four looks
        // like a valid type and shape alone would turn a quarter of a
        // proprietary bus into imaginary diagnostic sessions. Only the
        // identifiers ISO 15765-4 reserves are considered.
        if super::isotp::is_diagnostic_id(id, extended) && super::isotp::looks_like_isotp(payload) {
            let mut r = super::isotp::dissect_isotp(id, payload);
            let width = if extended { 8 } else { 3 };
            r.summary = format!("CAN 0x{id:0width$X} · {}", r.summary);
            return r;
        }
    }

    let width = if extended { 8 } else { 3 };
    DissectedResult {
        summary: format!("CAN 0x{id:0width$X} [{len}]{notes}{data_part}"),
        ..base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(id: u32, data: &[u8]) -> Vec<u8> {
        let mut v = id.to_be_bytes().to_vec();
        v.push(data.len() as u8);
        v.extend_from_slice(&[0, 0, 0]); // fd flags + reserved
        v.extend_from_slice(data);
        v
    }

    #[test]
    fn standard_frame() {
        let r = dissect_can(&frame(0x123, &[0xDE, 0xAD, 0xBE, 0xEF]));
        assert_eq!(r.protocol, Protocol::Can);
        assert_eq!(r.summary, "CAN 0x123 [4]  DE AD BE EF");
    }

    #[test]
    fn extended_frame_flagged() {
        let r = dissect_can(&frame(0x18DA_F110 | CAN_EFF_FLAG, &[0x01]));
        assert!(r.summary.contains("0x18DAF110"), "{}", r.summary);
        assert!(r.summary.contains("ext"), "{}", r.summary);
    }

    #[test]
    fn remote_request_has_no_data() {
        let r = dissect_can(&frame(0x7FF | CAN_RTR_FLAG, &[]));
        assert!(r.summary.contains("remote request"), "{}", r.summary);
        assert_eq!(r.summary, "CAN 0x7FF [0] (remote request)");
    }

    #[test]
    fn error_frame_flagged() {
        let r = dissect_can(&frame(CAN_ERR_FLAG, &[0; 8]));
        assert!(r.summary.contains("error frame"), "{}", r.summary);
    }

    #[test]
    fn fd_frame_by_length() {
        let payload = [0u8; 12];
        let r = dissect_can(&frame(0x100, &payload));
        assert!(r.summary.contains("FD"), "{}", r.summary);
    }

    #[test]
    fn truncated_frame_is_malformed() {
        let r = dissect_can(&[0, 0, 1]);
        assert!(matches!(r.protocol, Protocol::Unknown(_)));
    }

    /// An extended frame whose parameter group the standard defines is a truck
    /// message, and saying which one beats printing its identifier.
    #[test]
    fn a_known_j1939_frame_is_lifted_out_of_the_hex() {
        // 0x18FEEE00: engine temperature, from the engine.
        let r = dissect_can(&frame(0x18FE_EE00 | CAN_EFF_FLAG, &[0u8; 8]));
        assert_eq!(r.protocol, Protocol::J1939);
        assert_eq!(r.summary, "J1939 engine temperature 1 (from engine)");
    }

    /// An extended frame that is not J1939 must keep its identifier rather than
    /// be given an invented message name.
    #[test]
    fn an_unknown_extended_frame_stays_a_can_frame() {
        let r = dissect_can(&frame(0x18AB_0001 | CAN_EFF_FLAG, &[0x01, 0x02]));
        assert_eq!(r.protocol, Protocol::Can);
        assert!(r.summary.starts_with("CAN 0x18AB0001"), "{}", r.summary);
    }

    /// OBD-II owns its identifiers outright, so a scanner's traffic resolves to
    /// the value a mechanic would read.
    #[test]
    fn an_obd2_reply_is_lifted_out_of_the_hex() {
        let r = dissect_can(&frame(0x7E8, &[0x04, 0x41, 0x0C, 0x0B, 0xB8]));
        assert_eq!(r.protocol, Protocol::Obd2);
        assert_eq!(r.summary, "OBD-II engine speed — 750 rpm");
    }

    /// An ordinary 11-bit frame outside that range is still just a CAN frame.
    #[test]
    fn an_ordinary_standard_frame_stays_a_can_frame() {
        let r = dissect_can(&frame(0x123, &[0xDE, 0xAD]));
        assert_eq!(r.protocol, Protocol::Can);
        assert!(r.summary.starts_with("CAN 0x123"), "{}", r.summary);
    }

    /// A remote request carries no data, so there is nothing to interpret and
    /// it must not be handed to a higher dissector.
    #[test]
    fn a_remote_request_is_not_interpreted() {
        let r = dissect_can(&frame(0x7E8 | CAN_RTR_FLAG, &[]));
        assert_eq!(r.protocol, Protocol::Can);
    }
}
