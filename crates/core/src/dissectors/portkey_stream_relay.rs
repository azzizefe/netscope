use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_portkey_stream_relay(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Portkey Stream Relay (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("x-portkey") || raw.contains("portkey") && raw.contains("trace") {
            let end = raw.len().min(80);
            format!("Portkey Stream Relay: {}", &raw[..end])
        } else if raw.contains("virtual_key") && raw.contains("config") {
            let end = raw.len().min(80);
            format!("Portkey Stream Relay: {}", &raw[..end])
        } else {
            format!("Portkey Stream Relay ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::PortkeyStreamRelay,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_portkey_stream_relay_relay() {
        let buf = b"data: {\"x-portkey-trace-id\":\"abc\",\"virtual_key\":\"key-123\",\"config\":{}}";
        let r = dissect_portkey_stream_relay(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::PortkeyStreamRelay);
        assert!(r.summary.contains("Portkey"));
    }

    #[test]
    fn test_portkey_stream_relay_malformed() {
        let buf = b"x";
        let r = dissect_portkey_stream_relay(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
