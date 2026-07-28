use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

/// What the command specifier in the top three bits means.
///
/// The same three bits mean different things in each direction — CiA 301 calls
/// them the *client* command specifier and the *server* command specifier, and
/// they are not the same list. A `3` from the client is an upload segment; a
/// `3` from the server is the response to an initiate-download. Reading one as
/// the other reports the opposite operation, so the direction has to be known
/// before the byte can be named, and only the identifier carries it.
fn sdo_command_name(command: u8, server: bool) -> &'static str {
    match (command >> 5, server) {
        (4, _) => "Abort",
        (0, false) => "Download Segment",
        (1, false) => "Initiate Download",
        (2, false) => "Initiate Upload",
        (3, false) => "Upload Segment",
        (5, false) => "Block Upload",
        (6, false) => "Block Download",
        (0, true) => "Upload Segment response",
        (1, true) => "Download Segment response",
        (2, true) => "Initiate Upload response",
        (3, true) => "Initiate Download response",
        (5, true) => "Block Download response",
        (6, true) => "Block Upload response",
        _ => "unknown command",
    }
}

/// SDO abort codes.
fn sdo_abort_reason(abort: u32) -> &'static str {
    match abort {
        0x05030000 => "Toggle bit not alternated",
        0x05040000 => "SDO protocol timed out",
        0x05040001 => "Client/server command specifier invalid",
        0x05040002 => "Invalid block size",
        0x05040003 => "Invalid sequence number",
        0x06010000 => "Unsupported access",
        0x06010001 => "Attempt to read write-only object",
        0x06010002 => "Attempt to write read-only object",
        0x06020000 => "Object does not exist",
        0x06040041 => "Object cannot be mapped",
        0x06040042 => "PDO length exceeded",
        0x06060000 => "Access failed due to hardware error",
        0x06070010 => "Data type mismatch",
        0x06070012 => "Data type too long",
        0x06070013 => "Data type too short",
        0x06090011 => "Sub-index does not exist",
        0x06090030 => "Value range exceeded",
        0x08000000 => "General error",
        0x08000020 => "Data cannot be transferred",
        0x08000021 => "Local control causes data not available",
        0x08000022 => "Device state prevents data transfer",
        _ => "Unknown abort code",
    }
}

/// Dissect an SDO. `node` and `server` come from the COB-ID, which is the only
/// place either is carried — see [`sdo_command_name`] for why the direction has
/// to be known.
pub fn dissect_canopen_sdo(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    node: u8,
    server: bool,
) -> DissectedResult {
    let who = if server { "server" } else { "client" };
    let summary = if payload.len() < 4 {
        format!("CANopen SDO {who} — node {node} (malformed)")
    } else {
        let cmd = sdo_command_name(payload[0], server);
        // Index is little-endian across bytes 1-2, sub-index is byte 3.
        let index = u16::from_le_bytes([payload[1], payload[2]]);
        let subindex = payload[3];
        if payload[0] >> 5 == 4 && payload.len() >= 8 {
            let abort = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
            let reason = sdo_abort_reason(abort);
            format!(
                "CANopen SDO {cmd} — node {node} {index:#06X}:{subindex:#04X} \
                 abort 0x{abort:08X} ({reason})"
            )
        } else {
            format!("CANopen SDO {cmd} — node {node} {index:#06X}:{subindex:#04X}")
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::CanopenSdo,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A read of object 0x1000 (device type) — the request every CANopen
    /// master makes first.
    #[test]
    fn an_upload_request_names_the_object_it_reads() {
        let buf = &[0x40, 0x00, 0x10, 0x00, 0, 0, 0, 0];
        let r = dissect_canopen_sdo(None, None, 0, 0, buf, 10, false);
        assert_eq!(r.protocol, Protocol::CanopenSdo);
        assert_eq!(
            r.summary,
            "CANopen SDO Initiate Upload — node 10 0x1000:0x00"
        );
    }

    /// The same three bits mean different things in each direction. This is
    /// the pair that would otherwise be reported as its own opposite.
    #[test]
    fn the_direction_changes_what_the_command_byte_means() {
        let three = &[0x60, 0x00, 0x10, 0x00, 0, 0, 0, 0];
        assert!(dissect_canopen_sdo(None, None, 0, 0, three, 1, false)
            .summary
            .contains("Upload Segment"));
        assert!(dissect_canopen_sdo(None, None, 0, 0, three, 1, true)
            .summary
            .contains("Initiate Download response"));
    }

    /// An abort is why a configuration write failed, and the code is the
    /// reason — this is usually what the capture was taken for.
    #[test]
    fn an_abort_reports_its_reason() {
        let buf = &[0x80, 0x00, 0x10, 0x01, 0x00, 0x00, 0x03, 0x05];
        let r = dissect_canopen_sdo(None, None, 0, 0, buf, 4, true);
        assert!(r.summary.contains("Abort"), "{}", r.summary);
        assert!(r.summary.contains("Toggle bit"), "{}", r.summary);
    }

    #[test]
    fn a_truncated_sdo_still_names_its_node() {
        let r = dissect_canopen_sdo(None, None, 0, 0, &[0x40, 0x00], 9, false);
        assert_eq!(r.summary, "CANopen SDO client — node 9 (malformed)");
    }
}
