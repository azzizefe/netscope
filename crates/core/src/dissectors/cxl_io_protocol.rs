use std::net::IpAddr;

use crate::models::Protocol;
use crate::dissectors::DissectedResult;

pub fn dissect_cxl_io_protocol(
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
        let tag = u16::from_be_bytes([payload[2], payload[3]]);
        let _req_id = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let _addr = u64::from_be_bytes([
            payload[12], payload[13], payload[14], payload[15],
            0, 0, 0, 0,
        ]);
        summary = format!("CXL.io op={} tag={}",
            opcode, tag);
    } else {
        summary = "CXL.io (short frame)".into();
    }
    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::CxlIoProtocol,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_cxl_io_protocol_basic() {
        let mut buf = vec![0u8; 20];
        buf[0] = 1;
        buf[1] = 0x04; // MemRd
        buf[2..4].copy_from_slice(&0x1Au16.to_be_bytes());
        buf[8..12].copy_from_slice(&42u32.to_be_bytes());
        let r = dissect_cxl_io_protocol(
            Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            Some("10.0.0.2".parse::<IpAddr>().unwrap()),
            8500, 8500, &buf);
        assert_eq!(r.protocol, Protocol::CxlIoProtocol);
        assert!(r.summary.contains("op=4"));
        assert!(r.summary.contains("tag=26"));
    }
}
