use std::net::IpAddr;

use crate::dissectors::DissectedResult;
use crate::models::Protocol;

pub fn dissect_infiniband_ipoib_enhanced(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 12 {
        let _version = payload[0];
        let _flags = payload[1];
        let pkey = u16::from_be_bytes([payload[2], payload[3]]);
        let qpn = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let _len = u16::from_be_bytes([payload[10], payload[11]]);
        format!("IPoIB enhanced pkey=0x{:04x} qpn={}", pkey, qpn)
    } else {
        "IPoIB enhanced (short frame)".into()
    };
    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::InfinibandIpoibEnhanced,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_infiniband_ipoib_enhanced_basic() {
        let mut buf = vec![0u8; 16];
        buf[0] = 1;
        buf[1] = 0x80;
        buf[2..4].copy_from_slice(&0xFFFFu16.to_be_bytes());
        buf[4..8].copy_from_slice(&42u32.to_be_bytes());
        buf[10..12].copy_from_slice(&1500u16.to_be_bytes());
        let r = dissect_infiniband_ipoib_enhanced(
            Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            Some("10.0.0.2".parse::<IpAddr>().unwrap()),
            0,
            0,
            &buf,
        );
        assert_eq!(r.protocol, Protocol::InfinibandIpoibEnhanced);
        assert!(r.summary.contains("pkey=0xffff"));
        assert!(r.summary.contains("qpn=42"));
    }
}
