use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_profinet_cc_a(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "PROFINET CC-A over 5G (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("PROFINET") && (raw.contains("CC-A") || raw.contains("cc-a")) {
            let end = raw.len().min(80);
            format!("PROFINET CC-A over 5G: {}", &raw[..end])
        } else if raw.contains("PNIO") || raw.contains("pnio") {
            let end = raw.len().min(80);
            format!("PROFINET CC-A over 5G: {}", &raw[..end])
        } else {
            format!("PROFINET CC-A over 5G ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::ProfinetCcA,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profinet_cc_a_frame() {
        let buf = b"PROFINET:CC-A:PNIO:5G:cycle=2ms";
        let r = dissect_profinet_cc_a(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::ProfinetCcA);
        assert!(r.summary.contains("PROFINET"));
    }

    #[test]
    fn test_profinet_cc_a_malformed() {
        let buf = b"short";
        let r = dissect_profinet_cc_a(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
