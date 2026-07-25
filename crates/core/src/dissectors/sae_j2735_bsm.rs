use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_sae_j2735_bsm(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 10 {
        "SAE J2735 BSM (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("BSM") || raw.contains("BasicSafety") {
            let end = raw.len().min(80);
            format!("J2735 BSM: {}", &raw[..end])
        } else if raw.contains("J2735") || raw.contains("j2735") {
            let end = raw.len().min(80);
            format!("J2735 BSM: {}", &raw[..end])
        } else {
            format!("J2735 BSM ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SaeJ2735Bsm,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sae_j2735_bsm_message() {
        let buf = b"J2735:BSM:lat=40.7:lon=-74.0:speed=15.5";
        let r = dissect_sae_j2735_bsm(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::SaeJ2735Bsm);
        assert!(r.summary.contains("BSM"));
    }

    #[test]
    fn test_sae_j2735_bsm_malformed() {
        let buf = b"tooshort";
        let r = dissect_sae_j2735_bsm(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
