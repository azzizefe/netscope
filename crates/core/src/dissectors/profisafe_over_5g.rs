use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_profisafe_over_5g(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "PROFIsafe over 5G (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("PROFIsafe") || raw.contains("profisafe") || raw.contains("F-dest") {
            let end = raw.len().min(80);
            format!("PROFIsafe over 5G: {}", &raw[..end])
        } else if raw.contains("URLLC") && (raw.contains("safety") || raw.contains("io")) {
            let end = raw.len().min(80);
            format!("PROFIsafe over 5G: {}", &raw[..end])
        } else {
            format!("PROFIsafe over 5G ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::ProfisafeOver5g,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profisafe_over_5g_frame() {
        let buf = b"PROFIsafe:F-dest=42:safety:URLLC:seq=15";
        let r = dissect_profisafe_over_5g(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::ProfisafeOver5g);
        assert!(r.summary.contains("PROFIsafe"));
    }

    #[test]
    fn test_profisafe_over_5g_malformed() {
        let buf = b"short";
        let r = dissect_profisafe_over_5g(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
