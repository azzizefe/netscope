use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

/// CANopen NMT command bytes.
fn nmt_command_name(cs: u8) -> &'static str {
    match cs {
        0x01 => "Start Remote Node",
        0x02 => "Stop Remote Node",
        0x80 => "Enter Pre-Operational",
        0x81 => "Reset Node",
        0x82 => "Reset Communication",
        0x00 => "Boot-up",
        _ => "Unknown",
    }
}

pub fn dissect_canopen_nmt(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 2 {
        "CANopen NMT (malformed)".into()
    } else {
        let cs = payload[0];
        let node_id = payload[1];
        let cmd = nmt_command_name(cs);
        format!("CANopen NMT: {cmd} node={node_id:#04X}")
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::CanopenNmt,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nmt_start() {
        let buf = &[0x01, 0x05];
        let r = dissect_canopen_nmt(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::CanopenNmt);
        assert!(r.summary.contains("Start"));
        assert!(r.summary.contains("node=0x05"));
    }

    #[test]
    fn nmt_stop() {
        let buf = &[0x02, 0x01];
        let r = dissect_canopen_nmt(None, None, 0, 0, buf);
        assert!(r.summary.contains("Stop"));
    }

    #[test]
    fn nmt_reset() {
        let buf = &[0x81, 0x7F];
        let r = dissect_canopen_nmt(None, None, 0, 0, buf);
        assert!(r.summary.contains("Reset Node"));
    }

    #[test]
    fn nmt_malformed() {
        let buf = &[0x01];
        let r = dissect_canopen_nmt(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
