use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_opc_ua_pubsub_udp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "OPC UA PubSub UDP (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("OpcUa") || raw.contains("UADP") {
            let end = raw.len().min(80);
            format!("OPC UA PubSub UDP: {}", &raw[..end])
        } else if payload[0] == 0x71 {
            format!("OPC UA PubSub UADP frame ({})", super::bytes(payload.len() as u64))
        } else {
            format!("OPC UA PubSub UDP ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::OpcUaPubsubUdp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opc_ua_pubsub_udp_uadp() {
        let buf = b"\x71\x00\x00\x00\x00\x00\x00\x00";
        let r = dissect_opc_ua_pubsub_udp(None, None, 40000, 4841, buf);
        assert_eq!(r.protocol, Protocol::OpcUaPubsubUdp);
        assert!(r.summary.contains("UADP"));
    }

    #[test]
    fn test_opc_ua_pubsub_udp_malformed() {
        let buf = b"short";
        let r = dissect_opc_ua_pubsub_udp(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
