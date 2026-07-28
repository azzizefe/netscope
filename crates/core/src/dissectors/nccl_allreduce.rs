use std::net::IpAddr;

use crate::dissectors::DissectedResult;
use crate::models::Protocol;

pub fn dissect_nccl_allreduce(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 32 {
        let _version = payload[0];
        let algo = payload[1];
        let op = payload[2];
        let _dtype = payload[3];
        let count = u64::from_be_bytes([
            payload[4],
            payload[5],
            payload[6],
            payload[7],
            payload[8],
            payload[9],
            payload[10],
            payload[11],
        ]);
        let _root = u32::from_be_bytes([payload[12], payload[13], payload[14], payload[15]]);
        let rank = u32::from_be_bytes([payload[16], payload[17], payload[18], payload[19]]);
        let nranks = u32::from_be_bytes([payload[20], payload[21], payload[22], payload[23]]);
        let tag = u64::from_be_bytes([
            payload[24],
            payload[25],
            payload[26],
            payload[27],
            payload[28],
            payload[29],
            payload[30],
            payload[31],
        ]);
        format!(
            "NCCL allreduce algo={} op={} count={} rank={}/{} tag={}",
            algo, op, count, rank, nranks, tag
        )
    } else {
        "NCCL allreduce (short frame)".into()
    };
    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::NcclAllreduce,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_nccl_allreduce_basic() {
        let mut buf = vec![0u8; 32];
        buf[0] = 1;
        buf[1] = 0; // ring
        buf[2] = 0; // sum
        buf[4..12].copy_from_slice(&1048576u64.to_be_bytes());
        buf[16..20].copy_from_slice(&0u32.to_be_bytes());
        buf[20..24].copy_from_slice(&8u32.to_be_bytes());
        buf[24..32].copy_from_slice(&42u64.to_be_bytes());
        let r = dissect_nccl_allreduce(
            Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            Some("10.0.0.2".parse::<IpAddr>().unwrap()),
            5000,
            5000,
            &buf,
        );
        assert_eq!(r.protocol, Protocol::NcclAllreduce);
        assert!(r.summary.contains("algo=0"));
        assert!(r.summary.contains("count=1048576"));
        assert!(r.summary.contains("rank=0/8"));
        assert!(r.summary.contains("tag=42"));
    }
}
