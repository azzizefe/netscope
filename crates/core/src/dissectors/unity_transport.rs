use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_unity_transport(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        "Unity Transport (malformed)".into()
    } else {
        let version = payload[0];
        let channel = payload[1] >> 4;
        let packet_type = payload[1] & 0x0f;
        let sequence = u16::from_be_bytes([payload[2], payload[3]]);
        let type_name = match packet_type {
            0 => "Data",
            1 => "ACK",
            2 => "Connect",
            3 => "Disconnect",
            _ => "Unknown",
        };
        format!(
            "Unity Transport UTP {} v{} ch{} seq {}",
            type_name, version, channel, sequence
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::UnityTransport,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unity_transport_data() {
        let r = dissect_unity_transport(None, None, 9000, 9000, b"\x02\x00\x00\x01\xbe\xef");
        assert_eq!(r.protocol, Protocol::UnityTransport);
        assert!(r.summary.contains("Data"));
    }

    #[test]
    fn test_unity_transport_connect() {
        let r = dissect_unity_transport(None, None, 9000, 9000, b"\x02\x02\x00\x00");
        assert_eq!(r.protocol, Protocol::UnityTransport);
        assert!(r.summary.contains("Connect"));
    }

    #[test]
    fn test_unity_transport_ack() {
        let r = dissect_unity_transport(None, None, 9000, 9000, b"\x02\x01\x00\x05");
        assert_eq!(r.protocol, Protocol::UnityTransport);
        assert!(r.summary.contains("seq 5") && r.summary.contains("ACK"));
    }
}
