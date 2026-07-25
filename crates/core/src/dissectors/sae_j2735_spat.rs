use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_sae_j2735_spat(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 10 {
        "SAE J2735 SPAT (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("SPAT") || raw.contains("SignalPhase") {
            let end = raw.len().min(80);
            format!("J2735 SPAT: {}", &raw[..end])
        } else if raw.contains("intersection") && raw.contains("phase") {
            let end = raw.len().min(80);
            format!("J2735 SPAT: {}", &raw[..end])
        } else {
            format!("J2735 SPAT ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SaeJ2735Spat,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sae_j2735_spat_message() {
        let buf = b"J2735:SPAT:intersection=123:phase=4:state=green";
        let r = dissect_sae_j2735_spat(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::SaeJ2735Spat);
        assert!(r.summary.contains("SPAT"));
    }

    #[test]
    fn test_sae_j2735_spat_malformed() {
        let buf = b"tooshort";
        let r = dissect_sae_j2735_spat(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
