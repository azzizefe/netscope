use std::net::IpAddr;

use crate::models::Protocol;
use crate::dissectors::DissectedResult;

pub fn dissect_pytorch_rpc_framework(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let mut summary = String::new();
    if payload.len() >= 28 {
        let _version = payload[0];
        let msg_type = payload[1];
        let _flags = payload[2];
        let dst_rank = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let src_rank = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let req_id = u64::from_be_bytes([payload[12], payload[13], payload[14], payload[15], payload[16], payload[17], payload[18], payload[19]]);
        let _msg_len = u64::from_be_bytes([payload[20], payload[21], payload[22], payload[23], payload[24], payload[25], payload[26], payload[27]]);
        summary = format!("PyTorch RPC type={} src={} dst={} req={}",
            msg_type, src_rank, dst_rank, req_id);
    } else {
        summary = "PyTorch RPC (short frame)".into();
    }
    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::PytorchRpcFramework,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_pytorch_rpc_framework_basic() {
        let mut buf = vec![0u8; 28];
        buf[0] = 1;
        buf[1] = 0; // REQUEST
        buf[4..8].copy_from_slice(&3u32.to_be_bytes());
        buf[8..12].copy_from_slice(&0u32.to_be_bytes());
        buf[12..20].copy_from_slice(&100u64.to_be_bytes());
        buf[20..28].copy_from_slice(&256u64.to_be_bytes());
        let r = dissect_pytorch_rpc_framework(
            Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            Some("10.0.0.2".parse::<IpAddr>().unwrap()),
            29500, 29500, &buf);
        assert_eq!(r.protocol, Protocol::PytorchRpcFramework);
        assert!(r.summary.contains("type=0"));
        assert!(r.summary.contains("src=0"));
        assert!(r.summary.contains("dst=3"));
        assert!(r.summary.contains("req=100"));
    }
}
