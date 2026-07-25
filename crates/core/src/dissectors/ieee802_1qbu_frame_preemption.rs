use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_ieee802_1qbu_frame_preemption(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "802.1Qbu Frame Preemption (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("Qbu") || raw.contains("preemption") || raw.contains("mac_merge") {
            let end = raw.len().min(80);
            format!("802.1Qbu Frame Preemption: {}", &raw[..end])
        } else if raw.contains("fragment") || raw.contains("express") {
            format!("802.1Qbu Frame Preemption: {}", &raw[..raw.len().min(80)])
        } else {
            format!("802.1Qbu Frame Preemption ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ieee8021qbuFramePreemption,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ieee802_1qbu_preemption_config() {
        let buf = b"Qbu:mac_merge:express_fragment";
        let r = dissect_ieee802_1qbu_frame_preemption(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::Ieee8021qbuFramePreemption);
        assert!(r.summary.contains("Qbu"));
    }

    #[test]
    fn test_ieee802_1qbu_frame_preemption_malformed() {
        let buf = b"short";
        let r = dissect_ieee802_1qbu_frame_preemption(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
