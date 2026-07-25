use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_libp2p_webrtc_browser(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "libp2p WebRTC Browser (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("WebRTC") && (raw.contains("libp2p") || raw.contains("browser")) {
            let end = raw.len().min(80);
            format!("libp2p WebRTC Browser: {}", &raw[..end])
        } else if raw.contains("SDP") || raw.contains("ICE") && raw.contains("STUN") {
            let end = raw.len().min(80);
            format!("libp2p WebRTC Browser: {}", &raw[..end])
        } else {
            format!("libp2p WebRTC Browser ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Libp2pWebrtcBrowser,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_libp2p_webrtc_sdp() {
        let buf = b"WebRTC:libp2p:browser:SDP:ICE:STUN:peer=0xabc";
        let r = dissect_libp2p_webrtc_browser(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::Libp2pWebrtcBrowser);
        assert!(r.summary.contains("WebRTC Browser"));
    }

    #[test]
    fn test_libp2p_webrtc_malformed() {
        let buf = b"short";
        let r = dissect_libp2p_webrtc_browser(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
