use std::net::IpAddr;

use crate::models::Protocol;
use crate::dissectors::DissectedResult;

pub fn dissect_infiniband_rdmacm_v2(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary;
    if payload.len() >= 16 {
        let _version = payload[0];
        let msg_type = payload[1];
        let local_id = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let remote_id = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let _attr_mod = u32::from_be_bytes([payload[12], payload[13], payload[14], payload[15]]);
        summary = format!("IB RDMA CM v2 type={} local={} remote={}",
            msg_type, local_id, remote_id);
    } else {
        summary = "IB RDMA CM v2 (short frame)".into();
    }
    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::InfinibandRdmacmV2,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_infiniband_rdmacm_v2_basic() {
        let mut buf = vec![0u8; 20];
        buf[0] = 2;
        buf[1] = 1; // REQ
        buf[4..8].copy_from_slice(&1000u32.to_be_bytes());
        buf[8..12].copy_from_slice(&2000u32.to_be_bytes());
        let r = dissect_infiniband_rdmacm_v2(
            Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            None, 18515, 18515, &buf);
        assert_eq!(r.protocol, Protocol::InfinibandRdmacmV2);
        assert!(r.summary.contains("type=1"));
        assert!(r.summary.contains("local=1000"));
        assert!(r.summary.contains("remote=2000"));
    }
}
