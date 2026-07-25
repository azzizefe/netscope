use std::net::IpAddr;

use crate::models::Protocol;
use crate::dissectors::DissectedResult;

pub fn dissect_nvlink_fabric(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary;
    if payload.len() >= 8 {
        let version = payload[0];
        let cmd_type = payload[1];
        let txn_id = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        summary = format!("NVLink fabric ver={} cmd=0x{:02x} tx=#{}",
            version, cmd_type, txn_id);
    } else {
        summary = "NVLink fabric (short frame)".into();
    }
    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::NvlinkFabric,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_nvlink_fabric_basic() {
        let mut buf = vec![0u8; 16];
        buf[0] = 2; // version
        buf[1] = 0x10; // cmd type
        buf[4..8].copy_from_slice(&42u32.to_be_bytes());
        let r = dissect_nvlink_fabric(
            Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            Some("10.0.0.2".parse::<IpAddr>().unwrap()),
            5000, 5000, &buf);
        assert_eq!(r.protocol, Protocol::NvlinkFabric);
        assert!(r.summary.contains("ver=2"));
        assert!(r.summary.contains("cmd=0x10"));
        assert!(r.summary.contains("tx=#42"));
    }

    #[test]
    fn test_nvlink_fabric_short() {
        let buf = vec![0u8; 4];
        let r = dissect_nvlink_fabric(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::NvlinkFabric);
        assert!(r.summary.contains("short"));
    }
}
