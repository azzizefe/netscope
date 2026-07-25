use std::net::IpAddr;

use crate::models::Protocol;
use crate::dissectors::DissectedResult;

pub fn dissect_gpu_direct_storage(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary;
    if payload.len() >= 24 {
        let _version = payload[0];
        let cmd = payload[1];
        let _flags = payload[2];
        let _buf_addr = u64::from_be_bytes([
            payload[8], payload[9], payload[10], payload[11],
            payload[12], payload[13], payload[14], payload[15],
        ]);
        let size = u64::from_be_bytes([
            payload[16], payload[17], payload[18], payload[19],
            payload[20], payload[21], payload[22], payload[23],
        ]);
        summary = format!("GDS cmd={} size={}", cmd, size);
    } else {
        summary = "GDS (short frame)".into();
    }
    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::GpuDirectStorage,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_gpu_direct_storage_basic() {
        let mut buf = vec![0u8; 28];
        buf[0] = 1;
        buf[1] = 0x01; // DMA read
        buf[16..24].copy_from_slice(&65536u64.to_be_bytes());
        let r = dissect_gpu_direct_storage(
            Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            None, 5002, 5002, &buf);
        assert_eq!(r.protocol, Protocol::GpuDirectStorage);
        assert!(r.summary.contains("cmd=1"));
        assert!(r.summary.contains("size=65536"));
    }
}
