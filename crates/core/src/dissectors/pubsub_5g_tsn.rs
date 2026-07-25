use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_pubsub_5g_tsn(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "OPC UA PubSub 5G TSN (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("PubSub") && (raw.contains("5G") || raw.contains("TSN")) {
            let end = raw.len().min(80);
            format!("OPC UA PubSub 5G TSN: {}", &raw[..end])
        } else if raw.contains("opcua") && raw.contains("pubsub") && raw.contains("tsn") {
            let end = raw.len().min(80);
            format!("OPC UA PubSub 5G TSN: {}", &raw[..end])
        } else {
            format!("OPC UA PubSub 5G TSN ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Pubsub5gTsn,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pubsub_5g_tsn_frame() {
        let buf = b"PubSub:5G:TSN:opcua:writer=1:dataset=5";
        let r = dissect_pubsub_5g_tsn(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::Pubsub5gTsn);
        assert!(r.summary.contains("PubSub"));
    }

    #[test]
    fn test_pubsub_5g_tsn_malformed() {
        let buf = b"short";
        let r = dissect_pubsub_5g_tsn(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
