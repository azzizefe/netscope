use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_solana_tpu_proto(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "Solana TPU (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("TPU") && (raw.contains("tx") || raw.contains("transaction")) {
            let end = raw.len().min(80);
            format!("Solana TPU: {}", &raw[..end])
        } else if raw.contains("solana") && raw.contains("packet") && raw.contains("sig") {
            let end = raw.len().min(80);
            format!("Solana TPU: {}", &raw[..end])
        } else {
            format!("Solana TPU ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SolanaTpuProto,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solana_tpu_tx() {
        let buf = b"TPU:tx:sig=0xabc:packet:recent_blockhash=0xdef";
        let r = dissect_solana_tpu_proto(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::SolanaTpuProto);
        assert!(r.summary.contains("Solana TPU"));
    }

    #[test]
    fn test_solana_tpu_malformed() {
        let buf = b"tiny";
        let r = dissect_solana_tpu_proto(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
