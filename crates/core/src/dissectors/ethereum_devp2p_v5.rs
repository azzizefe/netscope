use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_ethereum_devp2p_v5(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Ethereum discv5 (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("discv5") || raw.contains("ENR") && raw.contains("node_id") {
            let end = raw.len().min(80);
            format!("Ethereum discv5: {}", &raw[..end])
        } else if raw.contains("findnode") || raw.contains("neighbors") || raw.contains("ping") {
            let end = raw.len().min(80);
            format!("Ethereum discv5: {}", &raw[..end])
        } else {
            format!("Ethereum discv5 ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::EthereumDevp2pV5,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethereum_discv5_ping() {
        let buf = b"discv5:ENR:node_id=0xabc:ping:seq=5";
        let r = dissect_ethereum_devp2p_v5(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::EthereumDevp2pV5);
        assert!(r.summary.contains("discv5"));
    }

    #[test]
    fn test_ethereum_discv5_malformed() {
        let buf = b"short";
        let r = dissect_ethereum_devp2p_v5(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
