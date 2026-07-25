use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_roblox_physics_replicator(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Roblox Physics Replicator (malformed)".into()
    } else {
        let obj_id = u32::from_be_bytes(payload[0..4].try_into().unwrap());
        let timestamp = u32::from_be_bytes(payload[4..8].try_into().unwrap());
        let body_count = if payload.len() > 8 { payload[8] } else { 0 };
        format!(
            "Roblox Physics Replicator obj=0x{:08x} ts={} bodies={}",
            obj_id, timestamp, body_count
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::RobloxPhysicsReplicator,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roblox_physics_replicator_basic() {
        let buf = vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2A, 0x03];
        let r = dissect_roblox_physics_replicator(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::RobloxPhysicsReplicator);
    }

    #[test]
    fn test_roblox_physics_replicator_malformed() {
        let buf = vec![0x00, 0x00, 0x00];
        let r = dissect_roblox_physics_replicator(None, None, 0, 0, &buf);
        assert!(r.summary.contains("malformed"));
    }
}
