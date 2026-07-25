use std::net::IpAddr;

use crate::models::Protocol;
use crate::dissectors::DissectedResult;

pub fn dissect_megatron_tp_overlap(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary;
    if payload.len() >= 32 {
        let _version = payload[0];
        let msg_type = payload[1];
        let tp_rank = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let tp_size = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let microbatch = u32::from_be_bytes([payload[12], payload[13], payload[14], payload[15]]);
        let _seq_len = u32::from_be_bytes([payload[16], payload[17], payload[18], payload[19]]);
        let _hidden_dim = u32::from_be_bytes([payload[20], payload[21], payload[22], payload[23]]);
        let tag = u64::from_be_bytes([payload[24], payload[25], payload[26], payload[27], payload[28], payload[29], payload[30], payload[31]]);
        summary = format!("Megatron TP overlap type={} tp={}/{} micro={} tag={}",
            msg_type, tp_rank, tp_size, microbatch, tag);
    } else {
        summary = "Megatron TP overlap (short frame)".into();
    }
    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::MegatronTpOverlap,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_megatron_tp_overlap_basic() {
        let mut buf = vec![0u8; 32];
        buf[0] = 1;
        buf[1] = 0; // fwd allreduce
        buf[4..8].copy_from_slice(&1u32.to_be_bytes());
        buf[8..12].copy_from_slice(&4u32.to_be_bytes());
        buf[12..16].copy_from_slice(&3u32.to_be_bytes());
        buf[24..32].copy_from_slice(&5u64.to_be_bytes());
        let r = dissect_megatron_tp_overlap(
            Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            Some("10.0.0.2".parse::<IpAddr>().unwrap()),
            9000, 9000, &buf);
        assert_eq!(r.protocol, Protocol::MegatronTpOverlap);
        assert!(r.summary.contains("type=0"));
        assert!(r.summary.contains("tp=1/4"));
        assert!(r.summary.contains("micro=3"));
        assert!(r.summary.contains("tag=5"));
    }
}
