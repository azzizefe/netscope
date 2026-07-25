use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_pir_spiral_stream(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "PIR SPIRAL Stream (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("SPIRAL") || raw.contains("spiral") && raw.contains("PIR") {
            let end = raw.len().min(80);
            format!("PIR SPIRAL Stream: {}", &raw[..end])
        } else if raw.contains("stream") && raw.contains("setup") && raw.contains("hint") {
            let end = raw.len().min(80);
            format!("PIR SPIRAL Stream: {}", &raw[..end])
        } else {
            format!("PIR SPIRAL Stream ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::PirSpiralStream,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pir_spiral_stream_setup() {
        let buf = b"SPIRAL:PIR:stream:setup:hint=0x1234:db_size=1GB";
        let r = dissect_pir_spiral_stream(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::PirSpiralStream);
        assert!(r.summary.contains("SPIRAL Stream"));
    }

    #[test]
    fn test_pir_spiral_stream_malformed() {
        let buf = b"short";
        let r = dissect_pir_spiral_stream(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
