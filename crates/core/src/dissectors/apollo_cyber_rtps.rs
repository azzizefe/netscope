use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_apollo_cyber_rtps(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Apollo Cyber RTPS (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("RTPS") || raw.contains("rtps") || raw.contains("Cyber") {
            let end = raw.len().min(80);
            format!("Apollo Cyber RTPS: {}", &raw[..end])
        } else if raw.contains("apollo") || raw.contains("Apollo") {
            let end = raw.len().min(80);
            format!("Apollo Cyber RTPS: {}", &raw[..end])
        } else {
            format!("Apollo Cyber RTPS ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::ApolloCyberRtps,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apollo_cyber_rtps_message() {
        let buf = b"RTPS:Apollo:Cyber:chassis:seq=100";
        let r = dissect_apollo_cyber_rtps(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::ApolloCyberRtps);
        assert!(r.summary.contains("Cyber"));
    }

    #[test]
    fn test_apollo_cyber_rtps_malformed() {
        let buf = b"tooshrt";
        let r = dissect_apollo_cyber_rtps(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
