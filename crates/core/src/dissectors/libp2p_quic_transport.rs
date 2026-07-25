use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_libp2p_quic_transport(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "libp2p QUIC Transport (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("libp2p") && (raw.contains("QUIC") || raw.contains("quic")) {
            let end = raw.len().min(80);
            format!("libp2p QUIC Transport: {}", &raw[..end])
        } else if raw.contains("WebTransport") || raw.contains("wt") && raw.contains("multiplex") {
            let end = raw.len().min(80);
            format!("libp2p QUIC Transport: {}", &raw[..end])
        } else {
            format!("libp2p QUIC Transport ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Libp2pQuicTransport,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_libp2p_quic_multiplex() {
        let buf = b"libp2p:QUIC:WebTransport:multiplex:stream=1";
        let r = dissect_libp2p_quic_transport(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::Libp2pQuicTransport);
        assert!(r.summary.contains("QUIC"));
    }

    #[test]
    fn test_libp2p_quic_malformed() {
        let buf = b"short";
        let r = dissect_libp2p_quic_transport(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
