use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_openai_realtime(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        "OpenAI Realtime (malformed)".into()
    } else {
        let preamble = &payload[..4];
        if preamble == b"{\"ty" || preamble == b"{\"ev" {
            let raw = String::from_utf8_lossy(payload);
            let end = raw.len().min(80);
            format!("OpenAI Realtime JSON: {}", &raw[..end])
        } else {
            format!("OpenAI Realtime {}B binary", payload.len())
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::OpenaiRealtime,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openai_realtime_json() {
        let buf = b"{\"type\":\"session.update\",\"session\":{}}";
        let r = dissect_openai_realtime(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::OpenaiRealtime);
        assert!(r.summary.contains("session.update"));
    }

    #[test]
    fn test_openai_realtime_malformed() {
        let buf = b"abc";
        let r = dissect_openai_realtime(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
