use std::net::IpAddr;

use crate::models::Protocol;
use crate::dissectors::DissectedResult;

pub fn dissect_megatron_pipeline_flush(
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
        let pp_rank = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let pp_size = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let layer_id = u32::from_be_bytes([payload[12], payload[13], payload[14], payload[15]]);
        let microbatch = u32::from_be_bytes([payload[16], payload[17], payload[18], payload[19]]);
        let epoch = u64::from_be_bytes([payload[20], payload[21], payload[22], payload[23], payload[24], payload[25], payload[26], payload[27]]);
        summary = format!("Megatron PP flush type={} pp={}/{} layer={} micro={} epoch={}",
            msg_type, pp_rank, pp_size, layer_id, microbatch, epoch);
    } else {
        summary = "Megatron PP flush (short frame)".into();
    }
    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::MegatronPipelineFlush,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_megatron_pipeline_flush_basic() {
        let mut buf = vec![0u8; 28];
        buf[0] = 1;
        buf[1] = 1; // flush token
        buf[4..8].copy_from_slice(&2u32.to_be_bytes());
        buf[8..12].copy_from_slice(&4u32.to_be_bytes());
        buf[12..16].copy_from_slice(&12u32.to_be_bytes());
        buf[16..20].copy_from_slice(&7u32.to_be_bytes());
        buf[20..28].copy_from_slice(&1u64.to_be_bytes());
        let r = dissect_megatron_pipeline_flush(
            Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            Some("10.0.0.2".parse::<IpAddr>().unwrap()),
            9001, 9001, &buf);
        assert_eq!(r.protocol, Protocol::MegatronPipelineFlush);
        assert!(r.summary.contains("type=1"));
        assert!(r.summary.contains("pp=2/4"));
        assert!(r.summary.contains("layer=12"));
        assert!(r.summary.contains("micro=7"));
        assert!(r.summary.contains("epoch=1"));
    }
}
