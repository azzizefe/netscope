use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_steam_remote_play_together(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "Steam Remote Play Together (malformed)".into()
    } else {
        let magic = u32::from_be_bytes(payload[..4].try_into().unwrap());
        let msg_type = u16::from_be_bytes(payload[4..6].try_into().unwrap());
        let client_id = u16::from_be_bytes(payload[6..8].try_into().unwrap());
        let seq = u32::from_be_bytes(payload[8..12].try_into().unwrap());
        let type_name = match msg_type {
            0x0001 => "VideoFrame",
            0x0002 => "AudioFrame",
            0x0003 => "ControllerInput",
            0x0004 => "ChatAudio",
            0x0005 => "ChatText",
            0x0006 => "KeyframeRequest",
            0x0007 => "StreamConfig",
            0x0008 => "ConnectionInfo",
            _ => "Unknown",
        };
        let is_rpt_magic = magic == 0x52505401 || magic == 0x52505402;
        let sub = if payload.len() >= 16 && msg_type == 0x0003 {
            let btn = u32::from_be_bytes(payload[12..16].try_into().unwrap());
            format!(" buttons=0x{:08x}", btn)
        } else if payload.len() >= 14 && (msg_type == 0x0001 || msg_type == 0x0002) {
            let size = u16::from_be_bytes(payload[12..14].try_into().unwrap());
            format!(" payload={}B", size)
        } else {
            String::new()
        };
        format!(
            "Steam RPT client={} msg={} seq={}{}{} len={}",
            client_id,
            type_name,
            seq,
            sub,
            if is_rpt_magic { "" } else { " (raw)" },
            payload.len(),
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SteamRemotePlayTogether,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_steam_rpt_video() {
        let mut buf = vec![0u8; 20];
        buf[..4].copy_from_slice(&0x52505401u32.to_be_bytes());
        buf[4..6].copy_from_slice(&1u16.to_be_bytes());
        buf[6..8].copy_from_slice(&1u16.to_be_bytes());
        buf[8..12].copy_from_slice(&42u32.to_be_bytes());
        buf[12..14].copy_from_slice(&1400u16.to_be_bytes());
        let r = dissect_steam_remote_play_together(None, None, 27036, 27036, &buf);
        assert_eq!(r.protocol, Protocol::SteamRemotePlayTogether);
        assert!(r.summary.contains("VideoFrame"));
    }

    #[test]
    fn test_steam_rpt_controller() {
        let mut buf = vec![0u8; 20];
        buf[..4].copy_from_slice(&0x52505401u32.to_be_bytes());
        buf[4..6].copy_from_slice(&3u16.to_be_bytes());
        buf[6..8].copy_from_slice(&2u16.to_be_bytes());
        buf[8..12].copy_from_slice(&10u32.to_be_bytes());
        buf[12..16].copy_from_slice(&0x0001_0002u32.to_be_bytes());
        let r = dissect_steam_remote_play_together(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::SteamRemotePlayTogether);
        assert!(r.summary.contains("ControllerInput"));
    }
}
