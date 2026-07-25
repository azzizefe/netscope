use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_phaser_heroiclabs(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 5 {
        "Nakama Binary (malformed)".into()
    } else {
        let opcode = payload[0];
        let seq = u32::from_be_bytes(payload[1..5].try_into().unwrap());
        let op_name = match opcode {
            0x00 => "Ping",
            0x01 => "Pong",
            0x02 => "MatchJoin",
            0x03 => "MatchLeave",
            0x04 => "MatchData",
            _ => "Unknown",
        };
        format!("Nakama Binary op={} seq={}", op_name, seq)
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::PhaserHeroiclabs,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phaser_heroiclabs_match_join() {
        let buf = vec![0x02, 0x00, 0x00, 0x00, 0x01];
        let r = dissect_phaser_heroiclabs(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::PhaserHeroiclabs);
        assert!(r.summary.contains("MatchJoin"));
    }

    #[test]
    fn test_phaser_heroiclabs_malformed() {
        let buf = vec![0x00, 0x00, 0x00];
        let r = dissect_phaser_heroiclabs(None, None, 0, 0, &buf);
        assert!(r.summary.contains("malformed"));
    }
}
