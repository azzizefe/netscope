use std::net::IpAddr;

use crate::models::Protocol;
use crate::dissectors::DissectedResult;

pub fn dissect_milvus_sealed_seg_stream(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let mut summary = String::new();
    if payload.len() >= 44 {
        let _version = payload[0];
        let msg_type = payload[1];
        let segment_id = u64::from_be_bytes([payload[4], payload[5], payload[6], payload[7], payload[8], payload[9], payload[10], payload[11]]);
        let partition_id = u64::from_be_bytes([payload[12], payload[13], payload[14], payload[15], payload[16], payload[17], payload[18], payload[19]]);
        let collection_id = u64::from_be_bytes([payload[20], payload[21], payload[22], payload[23], payload[24], payload[25], payload[26], payload[27]]);
        let chunk_idx = u32::from_be_bytes([payload[28], payload[29], payload[30], payload[31]]);
        let total_chunks = u32::from_be_bytes([payload[32], payload[33], payload[34], payload[35]]);
        let seq = u64::from_be_bytes([payload[36], payload[37], payload[38], payload[39], payload[40], payload[41], payload[42], payload[43]]);
        summary = format!("Milvus sealed seg type={} segment={} partition={} collection={} chunk={}/{} seq={}",
            msg_type, segment_id, partition_id, collection_id, chunk_idx, total_chunks, seq);
    } else {
        summary = "Milvus sealed seg (short frame)".into();
    }
    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::MilvusSealedSegStream,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_milvus_sealed_seg_stream_basic() {
        let mut buf = vec![0u8; 44];
        buf[0] = 1;
        buf[1] = 0; // StreamData
        buf[4..12].copy_from_slice(&42u64.to_be_bytes());
        buf[12..20].copy_from_slice(&7u64.to_be_bytes());
        buf[20..28].copy_from_slice(&1u64.to_be_bytes());
        buf[28..32].copy_from_slice(&0u32.to_be_bytes());
        buf[32..36].copy_from_slice(&10u32.to_be_bytes());
        buf[36..44].copy_from_slice(&5u64.to_be_bytes());
        let r = dissect_milvus_sealed_seg_stream(
            Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            Some("10.0.0.2".parse::<IpAddr>().unwrap()),
            19531, 19531, &buf);
        assert_eq!(r.protocol, Protocol::MilvusSealedSegStream);
        assert!(r.summary.contains("type=0"));
        assert!(r.summary.contains("segment=42"));
        assert!(r.summary.contains("partition=7"));
        assert!(r.summary.contains("collection=1"));
        assert!(r.summary.contains("chunk=0/10"));
        assert!(r.summary.contains("seq=5"));
    }
}
