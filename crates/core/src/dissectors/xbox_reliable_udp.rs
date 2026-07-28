use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_xbox_reliable_udp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Xbox Reliable UDP (malformed)".into()
    } else {
        let seq = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let ack = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let ack_mask = if payload.len() >= 12 {
            Some(u32::from_be_bytes([
                payload[8],
                payload[9],
                payload[10],
                payload[11],
            ]))
        } else {
            None
        };
        let mut s = format!("Xbox ReliableUDP seq={} ack={}", seq, ack);
        if let Some(mask) = ack_mask {
            s.push_str(&format!(" ackmask=0x{:08x}", mask));
        }
        s
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::XboxReliableUdp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xbox_reliable_udp() {
        let r = dissect_xbox_reliable_udp(
            None,
            None,
            3074,
            3074,
            b"\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\xff",
        );
        assert_eq!(r.protocol, Protocol::XboxReliableUdp);
        assert!(r.summary.contains("seq=1"));
        assert!(r.summary.contains("ack=2"));
    }
}
