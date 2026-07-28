use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_vrchat_udon_net(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        "VRChat UdonNet (malformed)".into()
    } else {
        let packet_type = payload[0];
        let seq = u16::from_be_bytes(payload[2..4].try_into().unwrap());
        format!("VRChat UdonNet seq={} type=0x{:02x}", seq, packet_type)
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::VrchatUdonNet,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vrchat_udon_net_basic() {
        let buf = vec![0x01, 0x00, 0x00, 0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
        let r = dissect_vrchat_udon_net(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::VrchatUdonNet);
    }

    #[test]
    fn test_vrchat_udon_net_malformed() {
        let buf = vec![0x01, 0x00];
        let r = dissect_vrchat_udon_net(None, None, 0, 0, &buf);
        assert!(r.summary.contains("malformed"));
    }
}
