use std::net::IpAddr;

use crate::models::Protocol;
use crate::dissectors::DissectedResult;

pub fn dissect_qdrant_quantization_sync(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let mut summary = String::new();
    if payload.len() >= 32 {
        let _version = payload[0];
        let seg_type = payload[1];
        let segment_id = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let quantization_type = payload[8];
        let vector_count = u64::from_be_bytes([payload[12], payload[13], payload[14], payload[15], payload[16], payload[17], payload[18], payload[19]]);
        let _chunk_size = u32::from_be_bytes([payload[20], payload[21], payload[22], payload[23]]);
        let seq = u64::from_be_bytes([payload[24], payload[25], payload[26], payload[27], payload[28], payload[29], payload[30], payload[31]]);
        summary = format!("Qdrant quant sync type={} segment={} qtype={} vectors={} seq={}",
            seg_type, segment_id, quantization_type, vector_count, seq);
    } else {
        summary = "Qdrant quant sync (short frame)".into();
    }
    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::QdrantQuantizationSync,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_qdrant_quantization_sync_basic() {
        let mut buf = vec![0u8; 32];
        buf[0] = 1;
        buf[1] = 0; // Binary quant
        buf[4..8].copy_from_slice(&5u32.to_be_bytes());
        buf[8] = 1; // Scalar
        buf[12..20].copy_from_slice(&10000u64.to_be_bytes());
        buf[24..32].copy_from_slice(&3u64.to_be_bytes());
        let r = dissect_qdrant_quantization_sync(
            Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            None, 6334, 6334, &buf);
        assert_eq!(r.protocol, Protocol::QdrantQuantizationSync);
        assert!(r.summary.contains("type=0"));
        assert!(r.summary.contains("segment=5"));
        assert!(r.summary.contains("qtype=1"));
        assert!(r.summary.contains("vectors=10000"));
        assert!(r.summary.contains("seq=3"));
    }
}
