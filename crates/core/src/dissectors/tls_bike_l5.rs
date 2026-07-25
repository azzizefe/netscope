use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_tls_bike_l5(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "TLS BIKE L5 (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("BIKE") || raw.contains("bike") || raw.contains("L5") {
            let end = raw.len().min(80);
            format!("TLS BIKE L5: {}", &raw[..end])
        } else if raw.contains("code-based") && raw.contains("KEM") {
            let end = raw.len().min(80);
            format!("TLS BIKE L5: {}", &raw[..end])
        } else {
            format!("TLS BIKE L5 ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TlsBikeL5,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_bike_l5_kem() {
        let buf = b"TLS:BIKE:L5:kem:ct=0xdead";
        let r = dissect_tls_bike_l5(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::TlsBikeL5);
        assert!(r.summary.contains("BIKE L5"));
    }

    #[test]
    fn test_tls_bike_l5_malformed() {
        let buf = b"short";
        let r = dissect_tls_bike_l5(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
