use std::net::IpAddr;

use crate::dissectors::DissectedResult;
use crate::models::Protocol;

pub fn dissect_nvme_over_fabrics_tcp(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() >= 16 {
        let pdu_type = payload[0];
        let _flags = payload[1];
        let _hlen = u16::from_be_bytes([payload[2], payload[3]]);
        let plen = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let cid = u16::from_be_bytes([payload[8], payload[9]]);
        format!("NVMe/TCP pdu=0x{:02x} cid={} plen={}", pdu_type, cid, plen)
    } else {
        "NVMe/TCP (short frame)".into()
    };
    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::NvmeOverFabricsTcp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_nvme_over_fabrics_tcp_basic() {
        let mut buf = vec![0u8; 20];
        buf[0] = 0x01; // ICReq PDU
        buf[4..8].copy_from_slice(&120u32.to_be_bytes());
        buf[8..10].copy_from_slice(&5u16.to_be_bytes());
        let r = dissect_nvme_over_fabrics_tcp(
            Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            Some("10.0.0.2".parse::<IpAddr>().unwrap()),
            4420,
            4420,
            &buf,
        );
        assert_eq!(r.protocol, Protocol::NvmeOverFabricsTcp);
        assert!(r.summary.contains("pdu=0x01"));
        assert!(r.summary.contains("cid=5"));
        assert!(r.summary.contains("plen=120"));
    }
}
