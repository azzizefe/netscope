use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_unity_ngo(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 5 {
        "Unity NGO (malformed)".into()
    } else {
        let msg_type = payload[0];
        let network_id = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
        let type_name = match msg_type {
            0 => "Spawn",
            1 => "Destroy",
            2 => "RPC",
            3 => "SyncVar",
            4 => "Custom",
            _ => "Unknown",
        };
        format!("Unity NGO {} netId {}", type_name, network_id)
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::UnityNgo,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unity_ngo_rpc() {
        let r = dissect_unity_ngo(None, None, 9001, 9001, b"\x02\x00\x00\x00\x2a\x01\x02\x03");
        assert_eq!(r.protocol, Protocol::UnityNgo);
        assert!(r.summary.contains("RPC"));
    }

    #[test]
    fn test_unity_ngo_spawn() {
        let r = dissect_unity_ngo(None, None, 9001, 9001, b"\x00\x00\x00\x00\x01");
        assert_eq!(r.protocol, Protocol::UnityNgo);
        assert!(r.summary.contains("Spawn"));
    }
}
