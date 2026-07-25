use std::net::IpAddr;

use crate::models::Protocol;
use crate::dissectors::DissectedResult;

pub fn dissect_cxl_cache_protocol(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary;
    if payload.len() >= 16 {
        let _version = payload[0];
        let opcode = payload[1];
        let tag = u16::from_be_bytes([payload[2], payload[3]]);
        let _chnl_id = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let _snoop_id = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
        summary = format!("CXL.cache op={} tag={}", opcode, tag);
    } else {
        summary = "CXL.cache (short frame)".into();
    }
    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::CxlCacheProtocol,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_cxl_cache_protocol_basic() {
        let mut buf = vec![0u8; 24];
        buf[0] = 1;
        buf[1] = 0x02; // SnpData
        buf[2..4].copy_from_slice(&0x07u16.to_be_bytes());
        buf[4..8].copy_from_slice(&3u32.to_be_bytes());
        buf[8..12].copy_from_slice(&0xAAu32.to_be_bytes());
        let r = dissect_cxl_cache_protocol(
            Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            Some("10.0.0.2".parse::<IpAddr>().unwrap()),
            8501, 8501, &buf);
        assert_eq!(r.protocol, Protocol::CxlCacheProtocol);
        assert!(r.summary.contains("op=2"));
        assert!(r.summary.contains("tag=7"));
    }
}
