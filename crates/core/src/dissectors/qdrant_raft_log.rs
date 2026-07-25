use std::net::IpAddr;

use crate::models::Protocol;
use crate::dissectors::DissectedResult;

pub fn dissect_qdrant_raft_log(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary;
    if payload.len() >= 40 {
        let _version = payload[0];
        let entry_type = payload[1];
        let term = u64::from_be_bytes([payload[4], payload[5], payload[6], payload[7], payload[8], payload[9], payload[10], payload[11]]);
        let index = u64::from_be_bytes([payload[12], payload[13], payload[14], payload[15], payload[16], payload[17], payload[18], payload[19]]);
        let peer_id = u32::from_be_bytes([payload[20], payload[21], payload[22], payload[23]]);
        let _prev_log_term = u64::from_be_bytes([payload[24], payload[25], payload[26], payload[27], payload[28], payload[29], payload[30], payload[31]]);
        let _prev_log_index = u64::from_be_bytes([payload[32], payload[33], payload[34], payload[35], payload[36], payload[37], payload[38], payload[39]]);
        let commit_index = u64::from_be_bytes([payload[40], payload[41], payload[42], payload[43], payload[44], payload[45], payload[46], payload[47]]);
        summary = format!("Qdrant Raft type={} term={} index={} peer={} commit={}",
            entry_type, term, index, peer_id, commit_index);
    } else {
        summary = "Qdrant Raft (short frame)".into();
    }
    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::QdrantRaftLog,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_qdrant_raft_log_basic() {
        let mut buf = vec![0u8; 48];
        buf[0] = 1;
        buf[1] = 0; // AppendEntries
        buf[4..12].copy_from_slice(&3u64.to_be_bytes());
        buf[12..20].copy_from_slice(&42u64.to_be_bytes());
        buf[20..24].copy_from_slice(&1u32.to_be_bytes());
        buf[40..48].copy_from_slice(&41u64.to_be_bytes());
        let r = dissect_qdrant_raft_log(
            Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            Some("10.0.0.2".parse::<IpAddr>().unwrap()),
            6333, 6333, &buf);
        assert_eq!(r.protocol, Protocol::QdrantRaftLog);
        assert!(r.summary.contains("type=0"));
        assert!(r.summary.contains("term=3"));
        assert!(r.summary.contains("index=42"));
        assert!(r.summary.contains("peer=1"));
        assert!(r.summary.contains("commit=41"));
    }
}
