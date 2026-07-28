use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_riot_vanguard_net(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 7 {
        "Riot Vanguard Net (malformed)".into()
    } else {
        let version = payload[0];
        let opcode = u16::from_be_bytes(payload[1..3].try_into().unwrap());
        let seq = u32::from_be_bytes(payload[3..7].try_into().unwrap());
        let op_name = match opcode {
            0x0001 => "Telemetry",
            0x0002 => "ProcessCheck",
            0x0003 => "Challenge",
            0x0004 => "Response",
            _ => "Unknown",
        };
        format!("Riot Vanguard Net v={} op={} seq={}", version, op_name, seq)
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::RiotVanguardNet,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_riot_vanguard_net_telemetry() {
        let buf = vec![0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01];
        let r = dissect_riot_vanguard_net(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::RiotVanguardNet);
        assert!(r.summary.contains("Telemetry"));
    }

    #[test]
    fn test_riot_vanguard_net_malformed() {
        let buf = vec![0x01, 0x00, 0x01, 0x00];
        let r = dissect_riot_vanguard_net(None, None, 0, 0, &buf);
        assert!(r.summary.contains("malformed"));
    }
}
