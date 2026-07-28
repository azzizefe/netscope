use std::net::IpAddr;

use crate::dissectors::DissectedResult;
use crate::models::Protocol;

pub fn dissect_nccl_broadcast(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 25 {
        let _version = payload[0];
        let algo = payload[1];
        let root = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let count = u64::from_be_bytes([
            payload[8],
            payload[9],
            payload[10],
            payload[11],
            payload[12],
            payload[13],
            payload[14],
            payload[15],
        ]);
        let _dtype = payload[16];
        let tag = u64::from_be_bytes([
            payload[17],
            payload[18],
            payload[19],
            payload[20],
            payload[21],
            payload[22],
            payload[23],
            payload[24],
        ]);
        format!(
            "NCCL broadcast algo={} root={} count={} tag={}",
            algo, root, count, tag
        )
    } else {
        "NCCL broadcast (short frame)".into()
    };
    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::NcclBroadcast,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_nccl_broadcast_basic() {
        let mut buf = vec![0u8; 25];
        buf[0] = 1;
        buf[1] = 0; // tree
        buf[4..8].copy_from_slice(&0u32.to_be_bytes());
        buf[8..16].copy_from_slice(&2097152u64.to_be_bytes());
        buf[16] = 0; // float32
        buf[17..25].copy_from_slice(&99u64.to_be_bytes());
        let r = dissect_nccl_broadcast(
            Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            Some("10.0.0.2".parse::<IpAddr>().unwrap()),
            5002,
            5002,
            &buf,
        );
        assert_eq!(r.protocol, Protocol::NcclBroadcast);
        assert!(r.summary.contains("algo=0"));
        assert!(r.summary.contains("root=0"));
        assert!(r.summary.contains("count=2097152"));
        assert!(r.summary.contains("tag=99"));
    }
}
