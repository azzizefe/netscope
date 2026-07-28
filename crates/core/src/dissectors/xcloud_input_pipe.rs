use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_xcloud_input_pipe(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "xCloud Input Pipe (malformed)".into()
    } else {
        let channel_id = u16::from_be_bytes(payload[..2].try_into().unwrap());
        let seq = u32::from_be_bytes(payload[4..8].try_into().unwrap());
        let msg_type = payload[2];
        let flags = payload[3];
        let type_name = match msg_type {
            0x01 => "ControllerState",
            0x02 => "TouchState",
            0x03 => "AccelSample",
            0x04 => "Telemetry",
            0x05 => "KeepAlive",
            0x81 => "GameMessage",
            _ => "Unknown",
        };
        let is_reliable = (flags & 0x01) != 0;
        let has_payload = (flags & 0x02) != 0;
        let payload_len = if has_payload && payload.len() > 8 {
            payload.len() - 8
        } else {
            0
        };
        format!(
            "xCloud Pipe ch={} msg={} seq={}{} data={}B len={}",
            channel_id,
            type_name,
            seq,
            if is_reliable { " RELIABLE" } else { "" },
            payload_len,
            payload.len(),
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::XcloudInputPipe,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xcloud_input_controller() {
        let mut buf = vec![0u8; 12];
        buf[..2].copy_from_slice(&1u16.to_be_bytes());
        buf[2] = 0x01;
        buf[3] = 0x03;
        buf[4..8].copy_from_slice(&100u32.to_be_bytes());
        let r = dissect_xcloud_input_pipe(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::XcloudInputPipe);
        assert!(r.summary.contains("ControllerState"));
        assert!(r.summary.contains("seq=100"));
    }

    #[test]
    fn test_xcloud_input_telemetry() {
        let mut buf = vec![0u8; 12];
        buf[..2].copy_from_slice(&2u16.to_be_bytes());
        buf[2] = 0x04;
        buf[3] = 0x01;
        buf[4..8].copy_from_slice(&50u32.to_be_bytes());
        let r = dissect_xcloud_input_pipe(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::XcloudInputPipe);
        assert!(r.summary.contains("Telemetry"));
    }
}
