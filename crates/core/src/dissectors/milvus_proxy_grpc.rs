use std::net::IpAddr;

use crate::dissectors::DissectedResult;
use crate::models::Protocol;

pub fn dissect_milvus_proxy_grpc(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 32 {
        let _version = payload[0];
        let msg_type = payload[1];
        let channel_id = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let node_id = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let segment_id = u64::from_be_bytes([
            payload[12],
            payload[13],
            payload[14],
            payload[15],
            payload[16],
            payload[17],
            payload[18],
            payload[19],
        ]);
        let batch_size = u32::from_be_bytes([payload[20], payload[21], payload[22], payload[23]]);
        let seq = u64::from_be_bytes([
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
            "Milvus proxy type={} channel={} node={} segment={} batch={} seq={}",
            msg_type, channel_id, node_id, segment_id, batch_size, seq
        )
    } else {
        "Milvus proxy (short frame)".into()
    };
    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::MilvusProxyGrpc,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_milvus_proxy_grpc_basic() {
        let mut buf = vec![0u8; 32];
        buf[0] = 1;
        buf[1] = 0; // Insert
        buf[4..8].copy_from_slice(&2u32.to_be_bytes());
        buf[8..12].copy_from_slice(&5u32.to_be_bytes());
        buf[12..20].copy_from_slice(&100u64.to_be_bytes());
        buf[20..24].copy_from_slice(&64u32.to_be_bytes());
        buf[24..32].copy_from_slice(&1u64.to_be_bytes());
        let r = dissect_milvus_proxy_grpc(
            Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            Some("10.0.0.2".parse::<IpAddr>().unwrap()),
            19530,
            19530,
            &buf,
        );
        assert_eq!(r.protocol, Protocol::MilvusProxyGrpc);
        assert!(r.summary.contains("type=0"));
        assert!(r.summary.contains("channel=2"));
        assert!(r.summary.contains("node=5"));
        assert!(r.summary.contains("segment=100"));
        assert!(r.summary.contains("batch=64"));
        assert!(r.summary.contains("seq=1"));
    }
}
