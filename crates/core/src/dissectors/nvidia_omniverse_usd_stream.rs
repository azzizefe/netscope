use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_nvidia_omniverse_usd_stream(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Omniverse USD Stream (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("usd") || raw.contains("USD") || raw.contains("Omniverse") {
            let end = raw.len().min(80);
            format!("Omniverse USD Stream: {}", &raw[..end])
        } else if raw.contains("stage") || raw.contains("prim") || raw.contains("layer") {
            format!("Omniverse USD Stream: {}", &raw[..raw.len().min(80)])
        } else {
            format!("Omniverse USD Stream ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::NvidiaOmniverseUsdStream,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nvidia_omniverse_usd_stream_stage() {
        let buf = b"USD:stage:prim:layer=root.usd";
        let r = dissect_nvidia_omniverse_usd_stream(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::NvidiaOmniverseUsdStream);
        assert!(r.summary.contains("USD"));
    }

    #[test]
    fn test_nvidia_omniverse_usd_stream_malformed() {
        let buf = b"short";
        let r = dissect_nvidia_omniverse_usd_stream(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
