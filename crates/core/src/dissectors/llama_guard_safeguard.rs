use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_llama_guard_safeguard(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Llama Guard Safeguard (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("llama_guard") || raw.contains("LlamaGuard") {
            let end = raw.len().min(80);
            format!("Llama Guard Safeguard: {}", &raw[..end])
        } else if raw.contains("safeguard") || raw.contains("unsafe") {
            format!("Llama Guard Safeguard: {}", &raw[..raw.len().min(80)])
        } else {
            format!("Llama Guard Safeguard ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::LlamaGuardSafeguard,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_llama_guard_safeguard_output() {
        let buf = b"{\"llama_guard\":\"safe\",\"safeguard\":\"harmlessness\"}";
        let r = dissect_llama_guard_safeguard(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::LlamaGuardSafeguard);
        assert!(r.summary.contains("llama_guard"));
    }

    #[test]
    fn test_llama_guard_safeguard_malformed() {
        let buf = b"short";
        let r = dissect_llama_guard_safeguard(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
