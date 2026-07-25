use std::net::IpAddr;

use crate::models::Protocol;
use crate::dissectors::DissectedResult;

pub fn dissect_horovod_elastic(
    _src_ip: Option<IpAddr>,
    _dst_ip: Option<IpAddr>,
    _src_port: u16,
    _dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary;
    if payload.len() >= 28 {
        let _version = payload[0];
        let msg_type = payload[1];
        let hostname_len = payload[3] as usize;
        let rank = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let world = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
        let epoch = u64::from_be_bytes([payload[12], payload[13], payload[14], payload[15], payload[16], payload[17], payload[18], payload[19]]);
        let _req_id = u64::from_be_bytes([payload[20], payload[21], payload[22], payload[23], payload[24], payload[25], payload[26], payload[27]]);
        let hostname = if hostname_len > 0 && 28 + hostname_len <= payload.len() {
            String::from_utf8_lossy(&payload[28..28 + hostname_len]).to_string()
        } else {
            String::new()
        };
        summary = format!("Horovod elastic type={} rank={}/{} epoch={} host={}",
            msg_type, rank, world, epoch, hostname);
    } else {
        summary = "Horovod elastic (short frame)".into();
    }
    DissectedResult {
        src_addr: _src_ip,
        dst_addr: _dst_ip,
        src_port: Some(_src_port),
        dst_port: Some(_dst_port),
        protocol: Protocol::HorovodElastic,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_horovod_elastic_basic() {
        let mut buf = vec![0u8; 36];
        buf[0] = 1;
        buf[1] = 2; // HEARTBEAT
        buf[3] = 5;
        buf[4..8].copy_from_slice(&2u32.to_be_bytes());
        buf[8..12].copy_from_slice(&4u32.to_be_bytes());
        buf[12..20].copy_from_slice(&1u64.to_be_bytes());
        buf[20..28].copy_from_slice(&12345u64.to_be_bytes());
        buf[28..33].copy_from_slice(b"node1");
        let r = dissect_horovod_elastic(
            Some("10.0.0.1".parse::<IpAddr>().unwrap()),
            None, 8000, 8000, &buf);
        assert_eq!(r.protocol, Protocol::HorovodElastic);
        assert!(r.summary.contains("type=2"));
        assert!(r.summary.contains("rank=2/4"));
        assert!(r.summary.contains("epoch=1"));
        assert!(r.summary.contains("host=node1"));
    }
}
