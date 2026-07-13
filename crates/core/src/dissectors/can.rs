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
        parts.push("FD".into());
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
}
