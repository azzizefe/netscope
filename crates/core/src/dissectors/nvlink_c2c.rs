use std::net::IpAddr;

use crate::models::Protocol;
use crate::dissectors::DissectedResult;

pub fn dissect_nvlink_c2c(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary;
    if payload.len() >= 12 {
        let _ver = payload[0];
        let proto_type = payload[1];
        let _flags = u16::from_be_bytes([payload[2], payload[3]]);
        let seq = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let data_len = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
        summary = format!("NVLink-C2C proto={} seq={} len={}",
            proto_type, seq, data_len);
    } else {
        summary = "NVLink-C2C (short frame)".into();
    }
    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::NvlinkC2c,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_nvlink_c2c_basic() {
        let mut buf = vec![0u8; 16];
        buf[0] = 1;
        buf[1] = 2;
        buf[4..8].copy_from_slice(&7u32.to_be_bytes());
        buf[8..12].copy_from_slice(&64u32.to_be_bytes());
        let r = dissect_nvlink_c2c(
            Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            Some("10.0.0.2".parse::<IpAddr>().unwrap()),
            7000, 7000, &buf);
        assert_eq!(r.protocol, Protocol::NvlinkC2c);
        assert!(r.summary.contains("proto=2"));
        assert!(r.summary.contains("seq=7"));
        assert!(r.summary.contains("len=64"));
    }
}
