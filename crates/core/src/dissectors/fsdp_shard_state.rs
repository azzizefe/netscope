use std::net::IpAddr;

use crate::models::Protocol;
use crate::dissectors::DissectedResult;

pub fn dissect_fsdp_shard_state(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary;
    if payload.len() >= 32 {
        let _version = payload[0];
        let msg_type = payload[1];
        let world_size = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let rank = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let shard_id = u32::from_be_bytes([payload[12], payload[13], payload[14], payload[15]]);
        let _param_count = u64::from_be_bytes([payload[16], payload[17], payload[18], payload[19], payload[20], payload[21], payload[22], payload[23]]);
        let seq = u64::from_be_bytes([payload[24], payload[25], payload[26], payload[27], payload[28], payload[29], payload[30], payload[31]]);
        summary = format!("FSDP shard type={} world={} rank={} shard={} seq={}",
            msg_type, world_size, rank, shard_id, seq);
    } else {
        summary = "FSDP shard (short frame)".into();
    }
    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::FsdpShardState,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_fsdp_shard_state_basic() {
        let mut buf = vec![0u8; 32];
        buf[0] = 1;
        buf[1] = 1; // unshard
        buf[4..8].copy_from_slice(&8u32.to_be_bytes());
        buf[8..12].copy_from_slice(&3u32.to_be_bytes());
        buf[12..16].copy_from_slice(&1u32.to_be_bytes());
        buf[24..32].copy_from_slice(&10u64.to_be_bytes());
        let r = dissect_fsdp_shard_state(
            Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            Some("10.0.0.2".parse::<IpAddr>().unwrap()),
            6000, 6000, &buf);
        assert_eq!(r.protocol, Protocol::FsdpShardState);
        assert!(r.summary.contains("type=1"));
        assert!(r.summary.contains("world=8"));
        assert!(r.summary.contains("rank=3"));
        assert!(r.summary.contains("shard=1"));
        assert!(r.summary.contains("seq=10"));
    }
}
