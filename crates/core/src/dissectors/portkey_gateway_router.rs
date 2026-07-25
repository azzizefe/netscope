use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_portkey_gateway_router(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        "Portkey Gateway Router (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("\"provider\"") || raw.contains("\"routing_strategy\"") {
            let end = raw.len().min(100);
            format!("Portkey Gateway Router: {}", &raw[..end])
        } else if raw.contains("/v1/router/") || raw.contains("x-portkey-") {
            format!("Portkey Gateway Router: {}", &raw[..raw.len().min(80)])
        } else {
            format!("Portkey Gateway Router ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::PortkeyGatewayRouter,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_portkey_gateway_router_request() {
        let buf = b"{\"provider\":\"openai\",\"routing_strategy\":\"latency-based\"}";
        let r = dissect_portkey_gateway_router(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::PortkeyGatewayRouter);
        assert!(r.summary.contains("provider"));
    }

    #[test]
    fn test_portkey_gateway_router_malformed() {
        let buf = b"abc";
        let r = dissect_portkey_gateway_router(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
