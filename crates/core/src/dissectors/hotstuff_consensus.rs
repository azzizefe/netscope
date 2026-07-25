use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_hotstuff_consensus(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "HotStuff Consensus (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("HotStuff") || raw.contains("hotstuff") && raw.contains("QC") {
            let end = raw.len().min(80);
            format!("HotStuff Consensus: {}", &raw[..end])
        } else if raw.contains("prepare") && raw.contains("precommit") && raw.contains("commit") {
            let end = raw.len().min(80);
            format!("HotStuff Consensus: {}", &raw[..end])
        } else {
            format!("HotStuff Consensus ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::HotstuffConsensus,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hotstuff_consensus_qc() {
        let buf = b"HotStuff:QC:prepare:precommit:commit:round=5";
        let r = dissect_hotstuff_consensus(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::HotstuffConsensus);
        assert!(r.summary.contains("HotStuff"));
    }

    #[test]
    fn test_hotstuff_consensus_malformed() {
        let buf = b"tiny";
        let r = dissect_hotstuff_consensus(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
