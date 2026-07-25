use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_mpc_ttp_preprocessing(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "MPC TTP Preprocessing (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("TTP") && (raw.contains("preprocessing") || raw.contains("triple")) {
            let end = raw.len().min(80);
            format!("MPC TTP Preprocessing: {}", &raw[..end])
        } else if raw.contains("Beaver") && raw.contains("mult") && raw.contains("rand") {
            let end = raw.len().min(80);
            format!("MPC TTP Preprocessing: {}", &raw[..end])
        } else {
            format!("MPC TTP Preprocessing ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::MpcTtpPreprocessing,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mpc_ttp_triple_gen() {
        let buf = b"TTP:preprocessing:Beaver:triple:mult:rand=a,b,c";
        let r = dissect_mpc_ttp_preprocessing(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::MpcTtpPreprocessing);
        assert!(r.summary.contains("TTP Preprocessing"));
    }

    #[test]
    fn test_mpc_ttp_preprocessing_malformed() {
        let buf = b"short";
        let r = dissect_mpc_ttp_preprocessing(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
