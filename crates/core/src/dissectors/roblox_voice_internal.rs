use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_roblox_voice_internal(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 5 {
        "Roblox Voice Internal (malformed)".into()
    } else {
        let flags = payload[0];
        let seq = u16::from_be_bytes(payload[1..3].try_into().unwrap());
        let audio_size = payload[4];
        let is_talker = (flags & 0x80) != 0;
        let has_position = (flags & 0x40) != 0;
        format!(
            "Roblox Voice Internal seq={}{}{} audio={}B",
            seq,
            if is_talker { " TALK" } else { "" },
            if has_position { " POS3D" } else { "" },
            audio_size
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::RobloxVoiceInternal,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roblox_voice_internal_talker() {
        let buf = vec![0x80, 0x00, 0x01, 0x00, 0x20, 0xAA, 0xBB];
        let r = dissect_roblox_voice_internal(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::RobloxVoiceInternal);
        assert!(r.summary.contains("TALK"));
    }

    #[test]
    fn test_roblox_voice_internal_spatial() {
        let buf = vec![0xC0, 0x00, 0x02, 0x00, 0x30, 0x01, 0x02, 0x03];
        let r = dissect_roblox_voice_internal(None, None, 0, 0, &buf);
        assert!(r.summary.contains("POS3D"));
    }

    #[test]
    fn test_roblox_voice_internal_malformed() {
        let buf = vec![0x00, 0x00, 0x00];
        let r = dissect_roblox_voice_internal(None, None, 0, 0, &buf);
        assert!(r.summary.contains("malformed"));
    }
}
