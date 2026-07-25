use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_epic_online_voice(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        "EOS Voice (malformed)".into()
    } else {
        let version = payload[0];
        let opcode = payload[1];
        let pkt_len = u16::from_be_bytes([payload[2], payload[3]]);
        let op_name = match opcode {
            0 => "Connect",
            1 => "ConnectAck",
            2 => "VoiceData",
            3 => "Disconnect",
            4 => "Ping",
            5 => "Pong",
            _ => "Unknown",
        };
        format!("EOS Voice v{} {} len={}", version, op_name, pkt_len)
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::EpicOnlineVoice,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eos_voice_connect() {
        let r = dissect_epic_online_voice(None, None, 27018, 27018, b"\x01\x00\x00\x08\xca\xfe");
        assert_eq!(r.protocol, Protocol::EpicOnlineVoice);
        assert!(r.summary.contains("Connect"));
    }

    #[test]
    fn test_eos_voice_data() {
        let r = dissect_epic_online_voice(None, None, 27018, 27018, b"\x01\x02\x00\x20\xde\xad\xbe\xef");
        assert_eq!(r.protocol, Protocol::EpicOnlineVoice);
        assert!(r.summary.contains("VoiceData"));
    }
}
