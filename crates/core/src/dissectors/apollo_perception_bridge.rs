use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_apollo_perception_bridge(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 6 {
        "Apollo Perception Bridge (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("perception") && raw.contains("planning") {
            let end = raw.len().min(80);
            format!("Apollo Perception Bridge: {}", &raw[..end])
        } else if raw.contains("bridge") && (raw.contains("apollo") || raw.contains("Apollo")) {
            let end = raw.len().min(80);
            format!("Apollo Perception Bridge: {}", &raw[..end])
        } else {
            format!("Apollo Perception Bridge ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::ApolloPerceptionBridge,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apollo_perception_bridge_msg() {
        let buf = b"apollo:bridge:perception:planning:lane_change";
        let r = dissect_apollo_perception_bridge(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::ApolloPerceptionBridge);
        assert!(r.summary.contains("bridge"));
    }

    #[test]
    fn test_apollo_perception_bridge_malformed() {
        let buf = b"smol";
        let r = dissect_apollo_perception_bridge(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
