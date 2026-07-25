use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_ethereum_consensus_p2p(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "Ethereum CL p2p (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("libp2p") && (raw.contains("beacon") || raw.contains("ssz")) {
            let end = raw.len().min(80);
            format!("Ethereum CL p2p: {}", &raw[..end])
        } else if raw.contains("BeaconBlock") || raw.contains("Attestation") || raw.contains("Aggregate") {
            let end = raw.len().min(80);
            format!("Ethereum CL p2p: {}", &raw[..end])
        } else {
            format!("Ethereum CL p2p ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::EthereumConsensusP2p,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethereum_cl_p2p_block() {
        let buf = b"libp2p:ssz:BeaconBlock:slot=100:proposer=0xabc";
        let r = dissect_ethereum_consensus_p2p(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::EthereumConsensusP2p);
        assert!(r.summary.contains("CL p2p"));
    }

    #[test]
    fn test_ethereum_cl_p2p_malformed() {
        let buf = b"tiny";
        let r = dissect_ethereum_consensus_p2p(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
