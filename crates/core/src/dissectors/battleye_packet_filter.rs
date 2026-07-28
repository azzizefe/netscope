use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_battleye_packet_filter(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 6 {
        "BattlEye Packet Filter (malformed)".into()
    } else {
        let msg_type = payload[0];
        let seq = u32::from_be_bytes(payload[2..6].try_into().unwrap());
        let type_name = match msg_type {
            0x00 => "Challenge",
            0x01 => "Response",
            0x02 => "Heartbeat",
            0x03 => "Kick",
            _ => "Unknown",
        };
        format!("BattlEye Packet Filter type={} seq={}", type_name, seq)
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::BattleyePacketFilter,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_battleye_packet_filter_heartbeat() {
        let buf = vec![0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let r = dissect_battleye_packet_filter(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::BattleyePacketFilter);
        assert!(r.summary.contains("Heartbeat"));
    }

    #[test]
    fn test_battleye_packet_filter_malformed() {
        let buf = vec![0x02, 0x00, 0x00];
        let r = dissect_battleye_packet_filter(None, None, 0, 0, &buf);
        assert!(r.summary.contains("malformed"));
    }
}
