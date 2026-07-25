use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_aegis_guard_llama(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Aegis Guard Llama (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("aegis") || raw.contains("Aegis") {
            let end = raw.len().min(80);
            format!("Aegis Guard Llama: {}", &raw[..end])
        } else if raw.contains("content_safety") || raw.contains("guard_score") {
            format!("Aegis Guard Llama: {}", &raw[..raw.len().min(80)])
        } else {
            format!("Aegis Guard Llama ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::AegisGuardLlama,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aegis_guard_llama_safety() {
        let buf = b"{\"aegis\":true,\"content_safety\":\"safe\",\"guard_score\":0.99}";
        let r = dissect_aegis_guard_llama(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::AegisGuardLlama);
        assert!(r.summary.contains("aegis"));
    }

    #[test]
    fn test_aegis_guard_llama_malformed() {
        let buf = b"short";
        let r = dissect_aegis_guard_llama(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
