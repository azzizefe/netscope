use std::net::IpAddr;

use crate::models::Protocol;
use crate::dissectors::DissectedResult;

pub fn dissect_pinecone_collection_stream(
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
        let shard_id = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let segment_id = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let record_count = u64::from_be_bytes([payload[12], payload[13], payload[14], payload[15], payload[16], payload[17], payload[18], payload[19]]);
        let seq = u64::from_be_bytes([payload[20], payload[21], payload[22], payload[23], payload[24], payload[25], payload[26], payload[27]]);
        summary = format!("Pinecone collection type={} shard={} segment={} records={} seq={}",
            msg_type, shard_id, segment_id, record_count, seq);
    } else {
        summary = "Pinecone collection (short frame)".into();
    }
    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::PineconeCollectionStream,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_pinecone_collection_stream_basic() {
        let mut buf = vec![0u8; 28];
        buf[0] = 1;
        buf[1] = 1; // Hydrate
        buf[4..8].copy_from_slice(&0u32.to_be_bytes());
        buf[8..12].copy_from_slice(&3u32.to_be_bytes());
        buf[12..20].copy_from_slice(&5000u64.to_be_bytes());
        buf[20..28].copy_from_slice(&42u64.to_be_bytes());
        let r = dissect_pinecone_collection_stream(
            Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            None, 5002, 5002, &buf);
        assert_eq!(r.protocol, Protocol::PineconeCollectionStream);
        assert!(r.summary.contains("type=1"));
        assert!(r.summary.contains("shard=0"));
        assert!(r.summary.contains("segment=3"));
        assert!(r.summary.contains("records=5000"));
        assert!(r.summary.contains("seq=42"));
    }
}
