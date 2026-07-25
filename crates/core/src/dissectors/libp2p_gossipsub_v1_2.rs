use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_libp2p_gossipsub_v1_2(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "libp2p GossipSub v1.2 (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("GossipSub") || raw.contains("gossipsub") && raw.contains("mesh") {
            let end = raw.len().min(80);
            format!("libp2p GossipSub v1.2: {}", &raw[..end])
        } else if raw.contains("IHAVE") || raw.contains("IWANT") || raw.contains("GRAFT") {
            let end = raw.len().min(80);
            format!("libp2p GossipSub v1.2: {}", &raw[..end])
        } else {
            format!("libp2p GossipSub v1.2 ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Libp2pGossipsubV12,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_libp2p_gossipsub_graft() {
        let buf = b"GossipSub:IHAVE:topic=/eth/beacon:mesh:seq=5";
        let r = dissect_libp2p_gossipsub_v1_2(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::Libp2pGossipsubV12);
        assert!(r.summary.contains("GossipSub"));
    }

    #[test]
    fn test_libp2p_gossipsub_malformed() {
        let buf = b"short";
        let r = dissect_libp2p_gossipsub_v1_2(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
