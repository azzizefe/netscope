use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_zk_stark_fri(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 16 {
        "zk-STARK FRI (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("STARK") && (raw.contains("FRI") || raw.contains("fri")) {
            let end = raw.len().min(80);
            format!("zk-STARK FRI: {}", &raw[..end])
        } else if raw.contains("Reed-Solomon") || raw.contains("IOPP") && raw.contains("query") {
            let end = raw.len().min(80);
            format!("zk-STARK FRI: {}", &raw[..end])
        } else {
            format!("zk-STARK FRI ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::ZkStarkFri,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zk_stark_fri_proof() {
        let buf = b"STARK:FRI:Reed-Solomon:IOPP:query=0xbe:round=4";
        let r = dissect_zk_stark_fri(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::ZkStarkFri);
        assert!(r.summary.contains("STARK FRI"));
    }

    #[test]
    fn test_zk_stark_fri_malformed() {
        let buf = b"tiny";
        let r = dissect_zk_stark_fri(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
