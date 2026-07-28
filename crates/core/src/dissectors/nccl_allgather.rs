use std::net::IpAddr;

use crate::dissectors::DissectedResult;
use crate::models::Protocol;

pub fn dissect_nccl_allgather(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 32 {
        let _version = payload[0];
        let algo = payload[1];
        let rank = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let nranks = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let recvcount = u64::from_be_bytes([
            payload[12],
            payload[13],
            payload[14],
            payload[15],
            payload[16],
            payload[17],
            payload[18],
            payload[19],
        ]);
        let _sendcount = u64::from_be_bytes([
            payload[20],
            payload[21],
            payload[22],
            payload[23],
            payload[24],
            payload[25],
            payload[26],
            payload[27],
        ]);
        let tag = u64::from_be_bytes([
            payload[28],
            payload[29],
            payload[30],
            payload[31],
            payload[32],
            payload[33],
            payload[34],
            payload[35],
        ]);
        let _ = nranks;
        let _ = recvcount;
        format!("NCCL allgather algo={} rank={} tag={}", algo, rank, tag)
    } else {
        "NCCL allgather (short frame)".into()
    };
    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::NcclAllgather,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_nccl_allgather_basic() {
        let mut buf = vec![0u8; 36];
        buf[0] = 1;
        buf[1] = 1; // tree
        buf[4..8].copy_from_slice(&2u32.to_be_bytes());
        buf[8..12].copy_from_slice(&4u32.to_be_bytes());
        buf[12..20].copy_from_slice(&524288u64.to_be_bytes());
        buf[28..36].copy_from_slice(&7u64.to_be_bytes());
        let r = dissect_nccl_allgather(
            Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            None,
            5001,
            5001,
            &buf,
        );
        assert_eq!(r.protocol, Protocol::NcclAllgather);
        assert!(r.summary.contains("algo=1"));
        assert!(r.summary.contains("rank=2"));
        assert!(r.summary.contains("tag=7"));
    }
}
