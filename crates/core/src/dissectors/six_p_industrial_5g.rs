use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_six_p_industrial_5g(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "6G-P Industrial 5G (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("6G-P") || raw.contains("6gp") || raw.contains("industrial_5g") {
            let end = raw.len().min(80);
            format!("6G-P Industrial 5G: {}", &raw[..end])
        } else if raw.contains("ultra-low-latency") || raw.contains("ULL") && raw.contains("fabric") {
            let end = raw.len().min(80);
            format!("6G-P Industrial 5G: {}", &raw[..end])
        } else {
            format!("6G-P Industrial 5G ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SixPIndustrial5g,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_six_p_industrial_5g_frame() {
        let buf = b"6G-P:industrial_5g:ULL:fabric:latency=100us";
        let r = dissect_six_p_industrial_5g(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::SixPIndustrial5g);
        assert!(r.summary.contains("6G-P"));
    }

    #[test]
    fn test_six_p_industrial_5g_malformed() {
        let buf = b"short";
        let r = dissect_six_p_industrial_5g(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
