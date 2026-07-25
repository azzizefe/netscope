use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_solana_gulf_stream(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "Solana Gulf Stream (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("gulf") && (raw.contains("stream") || raw.contains("mempool")) {
            let end = raw.len().min(80);
            format!("Solana Gulf Stream: {}", &raw[..end])
        } else if raw.contains("forward") && raw.contains("leader") && raw.contains("schedule") {
            let end = raw.len().min(80);
            format!("Solana Gulf Stream: {}", &raw[..end])
        } else {
            format!("Solana Gulf Stream ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SolanaGulfStream,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solana_gulf_stream_forward() {
        let buf = b"gulf:stream:mempool:forward:leader=validator1";
        let r = dissect_solana_gulf_stream(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::SolanaGulfStream);
        assert!(r.summary.contains("Gulf Stream"));
    }

    #[test]
    fn test_solana_gulf_stream_malformed() {
        let buf = b"tiny";
        let r = dissect_solana_gulf_stream(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
