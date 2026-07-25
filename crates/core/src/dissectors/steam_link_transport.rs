use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_steam_link_transport(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "Steam Link (malformed)".into()
    } else {
        let magic = u32::from_be_bytes(payload[..4].try_into().unwrap());
        let channel = payload[4];
        let flags = payload[5];
        let seq = u32::from_be_bytes(payload[6..10].try_into().unwrap());
        let _reserved = u16::from_be_bytes(payload[10..12].try_into().unwrap());
        let ch_name = match channel {
            0x01 => "Video",
            0x02 => "Audio",
            0x03 => "Input",
            0x04 => "Control",
            0x05 => "Cursor",
            0x06 => "Haptics",
            _ => "Unknown",
        };
        let is_sps = (flags & 0x01) != 0;
        let is_key = (flags & 0x02) != 0;
        let is_lossless = (flags & 0x04) != 0;
        let has_pts = (flags & 0x10) != 0;
        let pts_str = if has_pts && payload.len() >= 16 {
            let pts = u32::from_be_bytes(payload[12..16].try_into().unwrap());
            format!(" pts={}ms", pts)
        } else {
            String::new()
        };
        format!(
            "Steam Link ch={}({}) seq={}{}{}{}{} magic=0x{:08x} len={}",
            ch_name, channel, seq,
            if is_key { " KEY" } else { "" },
            if is_sps { " SPS" } else { "" },
            if is_lossless { " LOSSLESS" } else { "" },
            pts_str, magic, payload.len(),
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SteamLinkTransport,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_steam_link_video() {
        let mut buf = vec![0u8; 20];
        buf[..4].copy_from_slice(&0x534C494Eu32.to_be_bytes());
        buf[4] = 1;
        buf[5] = 0x02;
        buf[6..10].copy_from_slice(&100u32.to_be_bytes());
        buf[10..12].copy_from_slice(&0u16.to_be_bytes());
        buf[12..16].copy_from_slice(&16667u32.to_be_bytes());
        let r = dissect_steam_link_transport(None, None, 27031, 27036, &buf);
        assert_eq!(r.protocol, Protocol::SteamLinkTransport);
        assert!(r.summary.contains("Video"));
        assert!(r.summary.contains("KEY"));
    }

    #[test]
    fn test_steam_link_audio() {
        let mut buf = vec![0u8; 16];
        buf[..4].copy_from_slice(&0x534C494Eu32.to_be_bytes());
        buf[4] = 2;
        buf[5] = 0x04;
        buf[6..10].copy_from_slice(&200u32.to_be_bytes());
        let r = dissect_steam_link_transport(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::SteamLinkTransport);
        assert!(r.summary.contains("Audio"));
    }
}
