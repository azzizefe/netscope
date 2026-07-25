use std::net::IpAddr;

use crate::models::Protocol;
use crate::dissectors::DissectedResult;

pub fn dissect_weaviate_graphql_grpc(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let mut summary = String::new();
    if payload.len() >= 28 {
        let _version = payload[0];
        let msg_type = payload[1];
        let query_id = u64::from_be_bytes([payload[4], payload[5], payload[6], payload[7], payload[8], payload[9], payload[10], payload[11]]);
        let _class_len = payload[12];
        let batch_size = u32::from_be_bytes([payload[16], payload[17], payload[18], payload[19]]);
        let seq = u64::from_be_bytes([payload[20], payload[21], payload[22], payload[23], payload[24], payload[25], payload[26], payload[27]]);
        summary = format!("Weaviate gRPC type={} query={} batch={} seq={}",
            msg_type, query_id, batch_size, seq);
    } else {
        summary = "Weaviate gRPC (short frame)".into();
    }
    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::WeaviateGraphqlGrpc,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_weaviate_graphql_grpc_basic() {
        let mut buf = vec![0u8; 28];
        buf[0] = 1;
        buf[1] = 0; // Query
        buf[4..12].copy_from_slice(&100u64.to_be_bytes());
        buf[12] = 5;
        buf[16..20].copy_from_slice(&50u32.to_be_bytes());
        buf[20..28].copy_from_slice(&7u64.to_be_bytes());
        let r = dissect_weaviate_graphql_grpc(
            Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            Some("10.0.0.2".parse::<IpAddr>().unwrap()),
            6000, 6000, &buf);
        assert_eq!(r.protocol, Protocol::WeaviateGraphqlGrpc);
        assert!(r.summary.contains("type=0"));
        assert!(r.summary.contains("query=100"));
        assert!(r.summary.contains("batch=50"));
        assert!(r.summary.contains("seq=7"));
    }
}
