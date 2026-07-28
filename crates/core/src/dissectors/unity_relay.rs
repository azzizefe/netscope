use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_unity_relay(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        "Unity Relay (malformed)".into()
    } else {
        let msg_type = payload[0];
        let flags = payload[1];
        let relay_id = u16::from_be_bytes([payload[2], payload[3]]);
        let type_name = match msg_type {
            0 => "Bind",
            1 => "Connect",
            2 => "Relay",
            3 => "Ping",
            4 => "Disconnect",
            _ => "Unknown",
        };
        format!(
            "Unity Relay {} relayId {} flags 0x{:02x}",
            type_name, relay_id, flags
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::UnityRelay,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unity_relay_bind() {
        let r = dissect_unity_relay(None, None, 9700, 9700, b"\x00\x00\x00\x01");
        assert_eq!(r.protocol, Protocol::UnityRelay);
        assert!(r.summary.contains("Bind"));
    }

    #[test]
    fn test_unity_relay_relay() {
        let r = dissect_unity_relay(None, None, 9700, 9700, b"\x02\x01\x00\x0a\xbe\xef");
        assert_eq!(r.protocol, Protocol::UnityRelay);
        assert!(r.summary.contains("Relay"));
    }
}
