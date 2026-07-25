use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_etsi_gs_qkd_014(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "ETSI QKD 014 (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("QKD") && (raw.contains("014") || raw.contains("key_delivery")) {
            let end = raw.len().min(80);
            format!("ETSI GS QKD 014: {}", &raw[..end])
        } else if raw.contains("REST") && raw.contains("key_id") && raw.contains("kme") {
            let end = raw.len().min(80);
            format!("ETSI GS QKD 014: {}", &raw[..end])
        } else {
            format!("ETSI GS QKD 014 ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::EtsiGsQkd014,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_etsi_qkd_014_key_delivery() {
        let buf = b"ETSI:QKD:014:REST:kme=kv1:key_id=0xabcd";
        let r = dissect_etsi_gs_qkd_014(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::EtsiGsQkd014);
        assert!(r.summary.contains("QKD 014"));
    }

    #[test]
    fn test_etsi_qkd_014_malformed() {
        let buf = b"short";
        let r = dissect_etsi_gs_qkd_014(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
