use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_libp2p_kad_dht_v2(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "libp2p Kademlia DHT v2 (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("Kademlia") || raw.contains("kad") && raw.contains("DHT") {
            let end = raw.len().min(80);
            format!("libp2p Kademlia DHT v2: {}", &raw[..end])
        } else if raw.contains("FIND_NODE") || raw.contains("GET_PROVIDER") || raw.contains("ADD_PROVIDER") {
            let end = raw.len().min(80);
            format!("libp2p Kademlia DHT v2: {}", &raw[..end])
        } else {
            format!("libp2p Kademlia DHT v2 ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Libp2pKadDhtV2,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_libp2p_kad_find_node() {
        let buf = b"Kademlia:DHT:FIND_NODE:key=0xabcd:peer";
        let r = dissect_libp2p_kad_dht_v2(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::Libp2pKadDhtV2);
        assert!(r.summary.contains("Kademlia DHT"));
    }

    #[test]
    fn test_libp2p_kad_dht_malformed() {
        let buf = b"short";
        let r = dissect_libp2p_kad_dht_v2(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
