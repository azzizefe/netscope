use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_moonlight_rtsp_game(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "Moonlight RTSP (malformed)".into()
    } else {
        let body_str = std::str::from_utf8(payload).unwrap_or("");
        let mut first_line = body_str.lines().next().unwrap_or("");
        if first_line.len() > 120 {
            first_line = &first_line[..120];
        }
        let is_rtsp = body_str.starts_with("RTSP/")
            || body_str.starts_with("OPTIONS ")
            || body_str.starts_with("DESCRIBE ")
            || body_str.starts_with("SETUP ")
            || body_str.starts_with("PLAY ")
            || body_str.starts_with("PAUSE ")
            || body_str.starts_with("TEARDOWN ");
        let is_sunshine_ext = body_str.contains("X-Sunshine")
            || body_str.contains("x-moonlight")
            || body_str.contains("GameStream/");
        let method = if is_rtsp {
            first_line.to_string()
        } else {
            format!("Moonlight RTSP payload ({})", super::bytes(payload.len() as u64))
        };
        format!(
            "Moonlight RTSP {}{} len={}",
            method,
            if is_sunshine_ext { " [Sunshine]" } else { "" },
            payload.len(),
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::MoonlightRtspGame,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_moonlight_rtsp_options() {
        let payload = b"OPTIONS rtsp://192.168.1.100:47984/stream RTSP/1.0\r\nCSeq: 1\r\n\r\n";
        let r = dissect_moonlight_rtsp_game(None, None, 47984, 47989, payload);
        assert_eq!(r.protocol, Protocol::MoonlightRtspGame);
        assert!(r.summary.contains("OPTIONS"));
    }

    #[test]
    fn test_moonlight_rtsp_describe() {
        let payload = b"DESCRIBE rtsp://192.168.1.100:47984/stream RTSP/1.0\r\nCSeq: 2\r\nX-Sunshine-Tag: 1.0\r\n\r\n";
        let r = dissect_moonlight_rtsp_game(None, None, 47984, 47989, payload);
        assert_eq!(r.protocol, Protocol::MoonlightRtspGame);
        assert!(r.summary.contains("Sunshine"));
    }

    #[test]
    fn test_moonlight_rtsp_play() {
        let payload = b"PLAY rtsp://192.168.1.100:47984/stream RTSP/1.0\r\nCSeq: 4\r\nSession: 1234\r\n\r\n";
        let r = dissect_moonlight_rtsp_game(None, None, 47984, 47989, payload);
        assert_eq!(r.protocol, Protocol::MoonlightRtspGame);
        assert!(r.summary.contains("PLAY"));
    }
}
