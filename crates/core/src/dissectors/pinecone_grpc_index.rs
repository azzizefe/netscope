use std::net::IpAddr;

use crate::dissectors::DissectedResult;
use crate::models::Protocol;

pub fn dissect_pinecone_grpc_index(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 20 {
        let _version = payload[0];
        let msg_type = payload[1];
        let _ns_len = payload[2];
        let top_k = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let dimension = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let seq = u64::from_be_bytes([
            payload[12],
            payload[13],
            payload[14],
            payload[15],
            payload[16],
            payload[17],
            payload[18],
            payload[19],
        ]);
        format!(
            "Pinecone index type={} k={} dim={} seq={}",
            msg_type, top_k, dimension, seq
        )
    } else {
        "Pinecone index (short frame)".into()
    };
    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::PineconeGrpcIndex,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_pinecone_grpc_index_basic() {
        let mut buf = vec![0u8; 20];
        buf[0] = 1;
        buf[1] = 0; // Upsert
        buf[2] = 4;
        buf[4..8].copy_from_slice(&10u32.to_be_bytes());
        buf[8..12].copy_from_slice(&768u32.to_be_bytes());
        buf[12..20].copy_from_slice(&1u64.to_be_bytes());
        let r = dissect_pinecone_grpc_index(
            Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            Some("10.0.0.2".parse::<IpAddr>().unwrap()),
            5001,
            5001,
            &buf,
        );
        assert_eq!(r.protocol, Protocol::PineconeGrpcIndex);
        assert!(r.summary.contains("type=0"));
        assert!(r.summary.contains("k=10"));
        assert!(r.summary.contains("dim=768"));
        assert!(r.summary.contains("seq=1"));
    }
}
