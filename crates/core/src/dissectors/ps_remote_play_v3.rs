use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_ps_remote_play_v3(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "PS Remote Play v3 (malformed)".into()
    } else {
        let magic = u32::from_be_bytes(payload[..4].try_into().unwrap());
        let cmd = u16::from_be_bytes(payload[4..6].try_into().unwrap());
        let channel = payload[6];
        let flags = payload[7];
        let seq = u16::from_be_bytes(payload[8..10].try_into().unwrap());
        let ack = u16::from_be_bytes(payload[10..12].try_into().unwrap());
        let cmd_name = match cmd {
            0x0001 => "VideoFrame",
            0x0002 => "AudioFrame",
            0x0003 => "ControllerInput",
            0x0004 => "InitRequest",
            0x0005 => "InitResponse",
            0x0006 => "CodecConfig",
            0x0007 => "KeyframeRequest",
            0x0008 => "RttProbe",
            0x0009 => "RttResponse",
            0x000A => "SessionInfo",
            0x000B => "TouchInput",
            0x000C => "SixAxisSample",
            _ => "Unknown",
        };
        let is_ack = (flags & 0x01) != 0;
        let is_nak = (flags & 0x02) != 0;
        let is_key = (flags & 0x04) != 0;
        let ack_info = if is_ack {
            format!(" ack={}", ack)
        } else if is_nak {
            format!(" nak={}", ack)
        } else {
            String::new()
        };
        format!(
            "PS RemotePlay ch={} cmd={}(0x{:04x}) seq={}{}{} magic=0x{:08x} len={}",
            channel, cmd_name, cmd, seq, ack_info,
            if is_key { " KEY" } else { "" },
            magic, payload.len(),
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::PsRemotePlayV3,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ps_remote_play_video() {
        let mut buf = vec![0u8; 16];
        buf[..4].copy_from_slice(&0x505352u32.to_be_bytes());
        buf[4..6].copy_from_slice(&1u16.to_be_bytes());
        buf[6] = 1;
        buf[7] = 0x04;
        buf[8..10].copy_from_slice(&100u16.to_be_bytes());
        buf[10..12].copy_from_slice(&50u16.to_be_bytes());
        let r = dissect_ps_remote_play_v3(None, None, 9295, 9296, &buf);
        assert_eq!(r.protocol, Protocol::PsRemotePlayV3);
        assert!(r.summary.contains("VideoFrame"));
        assert!(r.summary.contains("KEY"));
    }

    #[test]
    fn test_ps_remote_play_input() {
        let mut buf = vec![0u8; 14];
        buf[..4].copy_from_slice(&0x505352u32.to_be_bytes());
        buf[4..6].copy_from_slice(&3u16.to_be_bytes());
        buf[6] = 2;
        buf[7] = 0;
        buf[8..10].copy_from_slice(&200u16.to_be_bytes());
        let r = dissect_ps_remote_play_v3(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::PsRemotePlayV3);
        assert!(r.summary.contains("ControllerInput"));
    }
}
