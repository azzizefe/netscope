use super::DissectedResult;
use crate::models::Protocol;
use std::net::IpAddr;

pub fn dissect_vllm_async_engine(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "vLLM Async Engine (malformed)".into()
    } else {
        let req_id = u64::from_be_bytes(payload[0..8].try_into().unwrap());
        let rest = if payload.len() > 8 {
            let raw = String::from_utf8_lossy(&payload[8..]);
            let end = raw.len().min(60);
            format!(": {}", &raw[..end])
        } else {
            String::new()
        };
        format!("vLLM Async Engine req=0x{:016x}{}", req_id, rest)
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::VllmAsyncEngine,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vllm_async_engine_basic() {
        let data = b"{\"prompt\":\"test\"}";
        let mut buf = vec![0u8; 8 + data.len()];
        buf[..8].copy_from_slice(&1u64.to_be_bytes());
        buf[8..].copy_from_slice(data);
        let r = dissect_vllm_async_engine(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::VllmAsyncEngine);
    }

    #[test]
    fn test_vllm_async_engine_malformed() {
        let buf = vec![0x00u8; 4];
        let r = dissect_vllm_async_engine(None, None, 0, 0, &buf);
        assert!(r.summary.contains("malformed"));
    }
}
