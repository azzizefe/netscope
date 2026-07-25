use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_bb84_qkd_classical(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "BB84 QKD Classical (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("BB84") || raw.contains("bb84") && raw.contains("sifting") {
            let end = raw.len().min(80);
            format!("BB84 QKD Classical: {}", &raw[..end])
        } else if raw.contains("basis") && raw.contains("reconciliation") {
            let end = raw.len().min(80);
            format!("BB84 QKD Classical: {}", &raw[..end])
        } else {
            format!("BB84 QKD Classical ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Bb84QkdClassical,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bb84_qkd_sifting() {
        let buf = b"BB84:sifting:basis=Z:signal=0xbe";
        let r = dissect_bb84_qkd_classical(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::Bb84QkdClassical);
        assert!(r.summary.contains("BB84"));
    }

    #[test]
    fn test_bb84_qkd_malformed() {
        let buf = b"short";
        let r = dissect_bb84_qkd_classical(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
