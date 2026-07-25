use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_opc_ua_gds_push(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "OPC UA GDS Push (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("GDS") || raw.contains("DiscoveryServer") || raw.contains("gds_push") {
            let end = raw.len().min(80);
            format!("OPC UA GDS Push: {}", &raw[..end])
        } else if raw.contains("RegisterServer") || raw.contains("FindServers") {
            format!("OPC UA GDS Push: {}", &raw[..raw.len().min(80)])
        } else {
            format!("OPC UA GDS Push ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::OpcUaGdsPush,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opc_ua_gds_push_register() {
        let buf = b"{\"GDS\":\"push\",\"RegisterServer\":{\"uri\":\"opc.tcp://example\"}}";
        let r = dissect_opc_ua_gds_push(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::OpcUaGdsPush);
        assert!(r.summary.contains("GDS"));
    }

    #[test]
    fn test_opc_ua_gds_push_malformed() {
        let buf = b"short";
        let r = dissect_opc_ua_gds_push(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
