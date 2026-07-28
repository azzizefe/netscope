use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_overwatch2_state_sync(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "Overwatch 2 State Sync (malformed)".into()
    } else {
        let opcode = u16::from_be_bytes(payload[..2].try_into().unwrap());
        let seq = u32::from_be_bytes(payload[4..8].try_into().unwrap());
        let tick = u32::from_be_bytes(payload[8..12].try_into().unwrap());
        let op_name = match opcode {
            0x0001 => "Heartbeat",
            0x0002 => "EntityUpdate",
            0x0003 => "EntitySpawn",
            0x0004 => "EntityDestroy",
            0x0005 => "WorldState",
            0x0006 => "PlayerState",
            0x0007 => "AbilityActivate",
            0x0008 => "ProjectileSync",
            0x0009 => "DamageEvent",
            0x000A => "GameState",
            _ => "Unknown",
        };
        format!(
            "OW2 StateSync op={}({}) seq={} tick={} len={}",
            op_name,
            opcode,
            seq,
            tick,
            payload.len(),
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Overwatch2StateSync,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overwatch2_state_sync() {
        let mut buf = vec![0u8; 16];
        buf[..2].copy_from_slice(&2u16.to_be_bytes());
        buf[2..4].copy_from_slice(&0u16.to_be_bytes());
        buf[4..8].copy_from_slice(&42u32.to_be_bytes());
        buf[8..12].copy_from_slice(&1500u32.to_be_bytes());
        let r = dissect_overwatch2_state_sync(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::Overwatch2StateSync);
        assert!(r.summary.contains("EntityUpdate"));
        assert!(r.summary.contains("seq=42"));
    }
}
