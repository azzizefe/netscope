use std::net::IpAddr;

use crate::models::Protocol;
use crate::dissectors::DissectedResult;

pub fn dissect_weaviate_hnsw_replication(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary;
    if payload.len() >= 28 {
        let _version = payload[0];
        let op_type = payload[1];
        let layer = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let entry_id = u64::from_be_bytes([payload[8], payload[9], payload[10], payload[11], payload[12], payload[13], payload[14], payload[15]]);
        let replica_id = u32::from_be_bytes([payload[16], payload[17], payload[18], payload[19]]);
        let seq = u64::from_be_bytes([payload[20], payload[21], payload[22], payload[23], payload[24], payload[25], payload[26], payload[27]]);
        summary = format!("Weaviate HNSW repl op={} layer={} entry={} replica={} seq={}",
            op_type, layer, entry_id, replica_id, seq);
    } else {
        summary = "Weaviate HNSW repl (short frame)".into();
    }
    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::WeaviateHnswReplication,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_weaviate_hnsw_replication_basic() {
        let mut buf = vec![0u8; 28];
        buf[0] = 1;
        buf[1] = 0; // Insert
        buf[4..8].copy_from_slice(&3u32.to_be_bytes());
        buf[8..16].copy_from_slice(&99u64.to_be_bytes());
        buf[16..20].copy_from_slice(&2u32.to_be_bytes());
        buf[20..28].copy_from_slice(&1u64.to_be_bytes());
        let r = dissect_weaviate_hnsw_replication(
            Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            Some("10.0.0.2".parse::<IpAddr>().unwrap()),
            6001, 6001, &buf);
        assert_eq!(r.protocol, Protocol::WeaviateHnswReplication);
        assert!(r.summary.contains("op=0"));
        assert!(r.summary.contains("layer=3"));
        assert!(r.summary.contains("entry=99"));
        assert!(r.summary.contains("replica=2"));
        assert!(r.summary.contains("seq=1"));
    }
}
