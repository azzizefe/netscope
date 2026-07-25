use std::net::IpAddr;

use crate::models::Protocol;
use crate::dissectors::DissectedResult;

pub fn dissect_gpu_direct_rdma(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let mut summary = String::new();
    if payload.len() >= 16 {
        let _version = payload[0];
        let opcode = payload[1];
        let _flags = payload[2];
        let peer_gpu = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let size = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let _rkey = u32::from_be_bytes([payload[12], payload[13], payload[14], payload[15]]);
        summary = format!("GPUDirect RDMA op={} peer_gpu={} size={}",
            opcode, peer_gpu, size);
    } else {
        summary = "GPUDirect RDMA (short frame)".into();
    }
    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::GpuDirectRdma,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_gpu_direct_rdma_basic() {
        let mut buf = vec![0u8; 20];
        buf[0] = 1;
        buf[1] = 0x03; // RDMA write
        buf[4..8].copy_from_slice(&1u32.to_be_bytes());
        buf[8..12].copy_from_slice(&4096u32.to_be_bytes());
        let r = dissect_gpu_direct_rdma(
            Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            Some("10.0.0.2".parse::<IpAddr>().unwrap()),
            5001, 5001, &buf);
        assert_eq!(r.protocol, Protocol::GpuDirectRdma);
        assert!(r.summary.contains("op=3"));
        assert!(r.summary.contains("peer_gpu=1"));
        assert!(r.summary.contains("size=4096"));
    }
}
