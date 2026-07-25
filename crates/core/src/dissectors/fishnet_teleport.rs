use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_fishnet_teleport(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 6 {
        "Fish-Networking Teleport (malformed)".into()
    } else {
        let channel = payload[0];
        let seq = u32::from_be_bytes(payload[1..5].try_into().unwrap());
        let flags = payload[5];
        let is_reliable = (flags & 0x01) != 0;
        format!(
            "Fish-Networking Teleport ch={} seq={}{}",
            channel,
            seq,
            if is_reliable { " REL" } else { "" }
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::FishnetTeleport,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fishnet_teleport_basic() {
        let buf = vec![0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0xAA, 0xBB];
        let r = dissect_fishnet_teleport(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::FishnetTeleport);
        assert!(r.summary.contains("REL"));
    }

    #[test]
    fn test_fishnet_teleport_malformed() {
        let buf = vec![0x00, 0x00, 0x00];
        let r = dissect_fishnet_teleport(None, None, 0, 0, &buf);
        assert!(r.summary.contains("malformed"));
    }
}
