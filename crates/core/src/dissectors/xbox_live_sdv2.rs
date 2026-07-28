use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_xbox_live_sdv2(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        "Xbox Live SDv2 (malformed)".into()
    } else {
        let msg_type = payload[0];
        let seq = u16::from_be_bytes([payload[1], payload[2]]);
        let flags = payload[3];
        let type_name = match msg_type {
            0x00 => "DataType",
            0x01 => "Connect",
            0x02 => "ConnectAck",
            0x03 => "ResetSeq",
            0x04 => "Ping",
            0x05 => "Pong",
            0x06 => "Reset",
            _ => "Unknown",
        };
        format!("Xbox SDv2 {} seq={} flags=0x{:02x}", type_name, seq, flags)
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::XboxLiveSdv2,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xbox_sdv2_data() {
        let r = dissect_xbox_live_sdv2(None, None, 3074, 3074, b"\x00\x01\x00\x00\xde\xad\xbe\xef");
        assert_eq!(r.protocol, Protocol::XboxLiveSdv2);
        assert!(r.summary.contains("DataType"));
    }

    #[test]
    fn test_xbox_sdv2_connect() {
        let r = dissect_xbox_live_sdv2(None, None, 3074, 3074, b"\x01\x00\x01\x00");
        assert_eq!(r.protocol, Protocol::XboxLiveSdv2);
        assert!(r.summary.contains("Connect"));
    }
}
