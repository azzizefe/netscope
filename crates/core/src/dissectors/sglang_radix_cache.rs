use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_sglang_radix_cache(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "SGLang Radix Cache (malformed)".into()
    } else {
        let prefix_len = u32::from_be_bytes(payload[0..4].try_into().unwrap());
        let req_id = u32::from_be_bytes(payload[4..8].try_into().unwrap());
        let extra = if payload.len() > 8 {
            let raw = String::from_utf8_lossy(&payload[8..]);
            let end = raw.len().min(50);
            format!(" {}", &raw[..end])
        } else {
            String::new()
        };
        format!(
            "SGLang Radix Cache prefix={}B req={}{}",
            prefix_len, req_id, extra
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SglangRadixCache,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sglang_radix_cache_basic() {
        let data = b"shared_prefix";
        let mut buf = vec![0u8; 8 + data.len()];
        buf[..4].copy_from_slice(&128u32.to_be_bytes());
        buf[4..8].copy_from_slice(&42u32.to_be_bytes());
        buf[8..].copy_from_slice(data);
        let r = dissect_sglang_radix_cache(None, None, 0, 0, &buf);
        assert_eq!(r.protocol, Protocol::SglangRadixCache);
        assert!(r.summary.contains("prefix=128"));
    }

    #[test]
    fn test_sglang_radix_cache_malformed() {
        let buf = vec![0x00u8; 4];
        let r = dissect_sglang_radix_cache(None, None, 0, 0, &buf);
        assert!(r.summary.contains("malformed"));
    }
}
