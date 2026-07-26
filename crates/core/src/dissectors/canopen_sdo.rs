use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// SDO command specifier.
fn sdo_command_name(ccs: u8) -> &'static str {
    match ccs >> 5 {
        0 => "SDO Segment Download",
        1 => "SDO Download Initiate",
        2 => "SDO Segment Upload",
        3 => "SDO Upload Initiate",
        4 => "SDO Abort Transfer",
        5 | 6 | 7 => "SDO Multiplexed",
        _ => "Unknown",
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

pub fn dissect_canopen_sdo(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        "CANopen SDO (malformed)".into()
    } else {
        let cmd = sdo_command_name(payload[0]);
        let index = ((payload[2] as u16) << 8) | payload[1] as u16;
        let subindex = payload[3];
        if cmd == "SDO Abort Transfer" && payload.len() >= 8 {
            let abort = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
            let reason = sdo_abort_reason(abort);
            format!("CANopen SDO: {cmd} index={index:#06X} sub={subindex:#04X} abort=0x{abort:08X} ({reason})")
        } else {
            format!("CANopen SDO: {cmd} index={index:#06X} sub={subindex:#04X}")
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

    #[test]
    fn sdo_upload_initiate() {
        let buf = &[0x60, 0x00, 0x10, 0x01];
        let r = dissect_canopen_sdo(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::CanopenSdo);
        assert!(r.summary.contains("Upload Initiate"));
        assert!(r.summary.contains("index=0x1000"));
    }

    #[test]
    fn sdo_download_initiate() {
        let buf = &[0x21, 0x00, 0x10, 0x00];
        let r = dissect_canopen_sdo(None, None, 0, 0, buf);
        assert!(r.summary.contains("Download Initiate"));
    }

    #[test]
    fn sdo_abort() {
        let buf = &[0x80, 0x00, 0x10, 0x01, 0x00, 0x00, 0x03, 0x05];
        let r = dissect_canopen_sdo(None, None, 0, 0, buf);
        assert!(r.summary.contains("Abort"));
        assert!(r.summary.contains("Toggle bit"));
    }

    #[test]
    fn sdo_malformed() {
        let buf = &[0x40, 0x00];
        let r = dissect_canopen_sdo(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
