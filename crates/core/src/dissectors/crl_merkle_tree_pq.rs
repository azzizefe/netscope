use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_crl_merkle_tree_pq(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "CRL Merkle Tree PQ (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("CRL") && (raw.contains("Merkle") || raw.contains("merkle")) {
            let end = raw.len().min(80);
            format!("CRL Merkle Tree PQ: {}", &raw[..end])
        } else if raw.contains("revocation") && raw.contains("tree") && raw.contains("pq") {
            let end = raw.len().min(80);
            format!("CRL Merkle Tree PQ: {}", &raw[..end])
        } else {
            format!("CRL Merkle Tree PQ ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::CrlMerkleTreePq,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crl_merkle_tree_pq_list() {
        let buf = b"CRL:Merkle:tree:pq:root=0xabcd:leaf=42";
        let r = dissect_crl_merkle_tree_pq(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::CrlMerkleTreePq);
        assert!(r.summary.contains("Merkle Tree"));
    }

    #[test]
    fn test_crl_merkle_tree_pq_malformed() {
        let buf = b"short";
        let r = dissect_crl_merkle_tree_pq(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
