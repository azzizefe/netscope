use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_eclipse_ditto_twin(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Eclipse Ditto Twin (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("Ditto") || raw.contains("ditto") || raw.contains("digital_twin") {
            let end = raw.len().min(80);
            format!("Eclipse Ditto Twin: {}", &raw[..end])
        } else if raw.contains("thing") || raw.contains("feature") || raw.contains("policy") {
            format!("Eclipse Ditto Twin: {}", &raw[..raw.len().min(80)])
        } else {
            format!("Eclipse Ditto Twin ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::EclipseDittoTwin,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eclipse_ditto_twin_crud() {
        let buf = b"{\"thingId\":\"Thermostat:1\",\"feature\":{\"temperature\":22.5}}";
        let r = dissect_eclipse_ditto_twin(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::EclipseDittoTwin);
        assert!(r.summary.contains("thing"));
    }

    #[test]
    fn test_eclipse_ditto_twin_malformed() {
        let buf = b"short";
        let r = dissect_eclipse_ditto_twin(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
