use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_google_aistudio_ws(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        "AI Studio WebSocket (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("\"prompt\"") || raw.contains("\"model\"") {
            let end = raw.len().min(80);
            format!("AI Studio WebSocket: {}", &raw[..end])
        } else {
            format!("AI Studio WebSocket {}B", payload.len())
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::GoogleAistudioWs,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_google_aistudio_ws_prompt() {
        let buf = b"{\"prompt\":\"Hello\",\"model\":\"gemini-2.0-flash\"}";
        let r = dissect_google_aistudio_ws(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::GoogleAistudioWs);
        assert!(r.summary.contains("gemini-2.0-flash"));
    }

    #[test]
    fn test_google_aistudio_ws_malformed() {
        let buf = b"abc";
        let r = dissect_google_aistudio_ws(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
