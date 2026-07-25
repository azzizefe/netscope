use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_openai_realtime_ws(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "OpenAI Realtime WS (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("realtime") && (raw.contains("audio") || raw.contains("text")) {
            let end = raw.len().min(80);
            format!("OpenAI Realtime WS: {}", &raw[..end])
        } else if raw.contains("transcript") || raw.contains("item") && raw.contains("response") {
            let end = raw.len().min(80);
            format!("OpenAI Realtime WS: {}", &raw[..end])
        } else {
            format!("OpenAI Realtime WS ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::OpenaiRealtimeWs,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openai_realtime_ws_audio() {
        let buf = b"realtime:audio:transcript:item=1:response=text";
        let r = dissect_openai_realtime_ws(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::OpenaiRealtimeWs);
        assert!(r.summary.contains("Realtime WS"));
    }

    #[test]
    fn test_openai_realtime_ws_malformed() {
        let buf = b"short";
        let r = dissect_openai_realtime_ws(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
