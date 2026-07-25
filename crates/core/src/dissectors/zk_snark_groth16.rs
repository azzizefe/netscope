use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_zk_snark_groth16(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 16 {
        "zk-SNARK Groth16 (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("Groth16") || raw.contains("groth16") || raw.contains("snark") {
            let end = raw.len().min(80);
            format!("zk-SNARK Groth16: {}", &raw[..end])
        } else if raw.contains("proof") && raw.contains("sigma") && raw.contains("G1") {
            let end = raw.len().min(80);
            format!("zk-SNARK Groth16: {}", &raw[..end])
        } else {
            format!("zk-SNARK Groth16 ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::ZkSnarkGroth16,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zk_snark_groth16_proof() {
        let buf = b"Groth16:proof:A=G1:B=G2:C=G1:pub=vk=0xabc";
        let r = dissect_zk_snark_groth16(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::ZkSnarkGroth16);
        assert!(r.summary.contains("Groth16"));
    }

    #[test]
    fn test_zk_snark_groth16_malformed() {
        let buf = b"tiny";
        let r = dissect_zk_snark_groth16(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
