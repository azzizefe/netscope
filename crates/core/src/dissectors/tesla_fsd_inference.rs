use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_tesla_fsd_inference(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Tesla FSD Inference (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("FSD") || raw.contains("fsd") || raw.contains("Tesla") {
            let end = raw.len().min(80);
            format!("Tesla FSD Inference: {}", &raw[..end])
        } else if raw.contains("inference") && (raw.contains("model") || raw.contains("tensor")) {
            let end = raw.len().min(80);
            format!("Tesla FSD Inference: {}", &raw[..end])
        } else {
            format!("Tesla FSD Inference ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TeslaFsdInference,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tesla_fsd_inference_request() {
        let buf = b"FSD:inference:tensor:model=v11.4:layer=42";
        let r = dissect_tesla_fsd_inference(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::TeslaFsdInference);
        assert!(r.summary.contains("FSD"));
    }

    #[test]
    fn test_tesla_fsd_inference_malformed() {
        let buf = b"tooshrt";
        let r = dissect_tesla_fsd_inference(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
