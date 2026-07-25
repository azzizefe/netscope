use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_unity_entities_netcode(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 6 {
        "Unity Entities Netcode (malformed)".into()
    } else {
        let snapshot_id = u16::from_be_bytes([payload[0], payload[1]]);
        let component_count = u16::from_be_bytes([payload[2], payload[3]]);
        let data_size = u16::from_be_bytes([payload[4], payload[5]]);
        format!("Unity Entities Netcode snapshot {} ({} components, {} bytes)", snapshot_id, component_count, data_size)
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::UnityEntitiesNetcode,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unity_entities_netcode() {
        let r = dissect_unity_entities_netcode(None, None, 9002, 9002, b"\x00\x01\x00\x05\x01\x00\xde\xad\xbe\xef");
        assert_eq!(r.protocol, Protocol::UnityEntitiesNetcode);
        assert!(r.summary.contains("snapshot 1"));
    }
}
