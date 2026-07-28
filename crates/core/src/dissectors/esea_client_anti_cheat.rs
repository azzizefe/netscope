use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_esea_client_anti_cheat(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "ESEA Anti-Cheat (malformed)".into()
    } else {
        let msg_type = payload[0];
        let version = payload[1];
        let seq = u32::from_be_bytes(payload[4..8].try_into().unwrap());
        let type_name = match msg_type {
            0x01 => "Telemetry",
            0x02 => "Challenge",
            0x03 => "Response",
            0x04 => "Heartbeat",
            _ => "Unknown",
        };
        format!(
            "ESEA Anti-Cheat type={} v={} seq={}",
            type_name, version, seq
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::EseaClientAntiCheat,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_esea_client_anti_cheat_challenge() {
        let buf = vec![0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let r = dissect_esea_client_anti_cheat(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::EseaClientAntiCheat);
        assert!(r.summary.contains("Challenge"));
    }

    #[test]
    fn test_esea_client_anti_cheat_malformed() {
        let buf = vec![0x02, 0x03, 0x00];
        let r = dissect_esea_client_anti_cheat(None, None, 0, 0, &buf);
        assert!(r.summary.contains("malformed"));
    }
}
