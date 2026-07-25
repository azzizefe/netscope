use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_fhe_tfhe_bootstrapping(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "FHE TFHE Bootstrapping (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("TFHE") && (raw.contains("boot") || raw.contains("bootstrapping")) {
            let end = raw.len().min(80);
            format!("FHE TFHE Bootstrapping: {}", &raw[..end])
        } else if raw.contains("gate") && raw.contains("LUT") && raw.contains("key_switch") {
            let end = raw.len().min(80);
            format!("FHE TFHE Bootstrapping: {}", &raw[..end])
        } else {
            format!("FHE TFHE Bootstrapping ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::FheTfheBootstrapping,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fhe_tfhe_bootstrap_gate() {
        let buf = b"TFHE:bootstrapping:gate=AND:LUT=0xbe:key_switch";
        let r = dissect_fhe_tfhe_bootstrapping(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::FheTfheBootstrapping);
        assert!(r.summary.contains("TFHE"));
    }

    #[test]
    fn test_fhe_tfhe_bootstrap_malformed() {
        let buf = b"short";
        let r = dissect_fhe_tfhe_bootstrapping(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
