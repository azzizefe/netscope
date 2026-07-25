use std::net::IpAddr;

use crate::models::Protocol;
use crate::dissectors::DissectedResult;

pub fn dissect_ucx_transport(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary;
    if payload.len() >= 20 {
        let _version = payload[0];
        let _flags = payload[1];
        let ep_id = u32::from_be_bytes([payload[2], payload[3], payload[4], payload[5]]);
        let conn_id = u32::from_be_bytes([payload[6], payload[7], payload[8], payload[9]]);
        let seq = u64::from_be_bytes([
            payload[10], payload[11], payload[12], payload[13],
            payload[14], payload[15], payload[16], payload[17],
        ]);
        let _data_len = u32::from_be_bytes([payload[18], payload[19], payload[20], payload[21]]);
        summary = format!("UCX transport ep={} conn={} seq={}",
            ep_id, conn_id, seq);
    } else {
        summary = "UCX transport (short frame)".into();
    }
    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::UcxTransport,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_ucx_transport_basic() {
        let mut buf = vec![0u8; 24];
        buf[0] = 1;
        buf[1] = 0x01;
        buf[2..6].copy_from_slice(&10u32.to_be_bytes());
        buf[6..10].copy_from_slice(&1u32.to_be_bytes());
        buf[10..18].copy_from_slice(&99u64.to_be_bytes());
        buf[18..22].copy_from_slice(&256u32.to_be_bytes());
        let r = dissect_ucx_transport(
            Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            Some("10.0.0.2".parse::<IpAddr>().unwrap()),
            9000, 9000, &buf);
        assert_eq!(r.protocol, Protocol::UcxTransport);
        assert!(r.summary.contains("ep=10"));
        assert!(r.summary.contains("conn=1"));
        assert!(r.summary.contains("seq=99"));
    }
}
