use std::net::IpAddr;

use crate::dissectors::DissectedResult;
use crate::models::Protocol;

pub fn dissect_deepspark_glootcp(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 32 {
        let _version = payload[0];
        let op_type = payload[1];
        let root = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let rank = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let world = u32::from_be_bytes([payload[12], payload[13], payload[14], payload[15]]);
        let data_len = u64::from_be_bytes([
            payload[16],
            payload[17],
            payload[18],
            payload[19],
            payload[20],
            payload[21],
            payload[22],
            payload[23],
        ]);
        let slot = u64::from_be_bytes([
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
            "DeepSpeed Gloo op={} root={} rank={}/{} len={} slot={}",
            op_type, root, rank, world, data_len, slot
        )
    } else {
        "DeepSpeed Gloo (short frame)".into()
    };
    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::DeepsparkGlootcp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_deepspark_glootcp_basic() {
        let mut buf = vec![0u8; 32];
        buf[0] = 1;
        buf[1] = 0; // allreduce
        buf[4..8].copy_from_slice(&0u32.to_be_bytes());
        buf[8..12].copy_from_slice(&1u32.to_be_bytes());
        buf[12..16].copy_from_slice(&4u32.to_be_bytes());
        buf[16..24].copy_from_slice(&262144u64.to_be_bytes());
        buf[24..32].copy_from_slice(&3u64.to_be_bytes());
        let r = dissect_deepspark_glootcp(
            Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            Some("10.0.0.2".parse::<IpAddr>().unwrap()),
            7000,
            7000,
            &buf,
        );
        assert_eq!(r.protocol, Protocol::DeepsparkGlootcp);
        assert!(r.summary.contains("op=0"));
        assert!(r.summary.contains("root=0"));
        assert!(r.summary.contains("rank=1/4"));
        assert!(r.summary.contains("len=262144"));
        assert!(r.summary.contains("slot=3"));
    }
}
