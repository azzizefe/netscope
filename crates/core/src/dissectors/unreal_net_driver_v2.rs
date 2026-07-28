use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_unreal_net_driver_v2(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Unreal NetDriverV2 (malformed)".into()
    } else {
        let channel_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let packet_id = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let extra = if payload.len() > 8 {
            payload.len() - 8
        } else {
            0
        };
        format!(
            "Unreal NetDriverV2 channel {} packet {} ({} ext bytes)",
            channel_id, packet_id, extra
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::UnrealNetDriverV2,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unreal_net_driver_v2() {
        let r = dissect_unreal_net_driver_v2(
            None,
            None,
            7777,
            7778,
            b"\x00\x00\x00\x01\x00\x00\x00\x2a\xde\xad",
        );
        assert_eq!(r.protocol, Protocol::UnrealNetDriverV2);
        assert!(r.summary.contains("channel 1"));
    }
}
