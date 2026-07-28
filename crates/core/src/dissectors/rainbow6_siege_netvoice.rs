use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_rainbow6_siege_netvoice(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "R6 Siege NetVoice (malformed)".into()
    } else {
        let magic = u32::from_be_bytes(payload[..4].try_into().unwrap());
        let voice_seq = u16::from_be_bytes(payload[4..6].try_into().unwrap());
        let flags = payload[6];
        let codec = payload[7];
        let data_len = payload.len().saturating_sub(8);
        let codec_name = match codec {
            0x00 => "Opus",
            0x01 => "Silk",
            0x02 => "Speex",
            0x03 => "RawPCM",
            _ => "Unknown",
        };
        let is_encrypted = (flags & 0x80) != 0;
        let is_talk = (flags & 0x01) != 0;
        let is_team = (flags & 0x02) != 0;
        let is_muted = (flags & 0x04) != 0;
        format!(
            "R6 NetVoice magic=0x{:08x} seq={} codec={}{}{}{}{} data={}B",
            magic,
            voice_seq,
            codec_name,
            if is_encrypted { " ENCRYPTED" } else { "" },
            if is_talk { " TALK" } else { "" },
            if is_team { " TEAM" } else { "" },
            if is_muted { " MUTED" } else { "" },
            data_len,
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Rainbow6SiegeNetvoice,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_r6_netvoice() {
        let payload = b"\x52\x36\x56\x4f\x00\x01\x83\x00\xde\xad\xbe\xef";
        let r = dissect_rainbow6_siege_netvoice(None, None, 0, 0, payload);
        assert_eq!(r.protocol, Protocol::Rainbow6SiegeNetvoice);
        assert!(r.summary.contains("seq=1"));
        assert!(r.summary.contains("Opus"));
    }

    #[test]
    fn test_r6_netvoice_team_talk() {
        let payload = b"\x52\x36\x56\x4f\x00\x02\x03\x02\xde\xad";
        let r = dissect_rainbow6_siege_netvoice(None, None, 0, 0, payload);
        assert_eq!(r.protocol, Protocol::Rainbow6SiegeNetvoice);
        assert!(r.summary.contains("TEAM"));
        assert!(r.summary.contains("TALK"));
    }
}
