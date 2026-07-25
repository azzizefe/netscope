use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_zk_snark_plonk(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 16 {
        "zk-SNARK PLONK (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("PLONK") || raw.contains("plonk") && raw.contains("permutation") {
            let end = raw.len().min(80);
            format!("zk-SNARK PLONK: {}", &raw[..end])
        } else if raw.contains("witness") && raw.contains("polynomial") && raw.contains("opening") {
            let end = raw.len().min(80);
            format!("zk-SNARK PLONK: {}", &raw[..end])
        } else {
            format!("zk-SNARK PLONK ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::ZkSnarkPlonk,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zk_snark_plonk_proof() {
        let buf = b"PLONK:permutation:witness:polynomial:opening=0xbe";
        let r = dissect_zk_snark_plonk(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::ZkSnarkPlonk);
        assert!(r.summary.contains("PLONK"));
    }

    #[test]
    fn test_zk_snark_plonk_malformed() {
        let buf = b"tiny";
        let r = dissect_zk_snark_plonk(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
