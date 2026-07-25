use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_ethereum_blob_sidecar(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "Ethereum Blob Sidecar (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("blob") && (raw.contains("4844") || raw.contains("sidecar")) {
            let end = raw.len().min(80);
            format!("Ethereum Blob Sidecar: {}", &raw[..end])
        } else if raw.contains("BlobTx") || raw.contains("commitment") && raw.contains("proof") {
            let end = raw.len().min(80);
            format!("Ethereum Blob Sidecar: {}", &raw[..end])
        } else {
            format!("Ethereum Blob Sidecar ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::EthereumBlobSidecar,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethereum_blob_sidecar_gossip() {
        let buf = b"4844:blob:sidecar:commitment=0xabc:proof=0xdef";
        let r = dissect_ethereum_blob_sidecar(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::EthereumBlobSidecar);
        assert!(r.summary.contains("Blob Sidecar"));
    }

    #[test]
    fn test_ethereum_blob_sidecar_malformed() {
        let buf = b"tiny";
        let r = dissect_ethereum_blob_sidecar(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
