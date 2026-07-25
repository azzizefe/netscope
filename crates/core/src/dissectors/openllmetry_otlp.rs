use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_openllmetry_otlp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 5 {
        "OpenLLMetry OTLP (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("\"llm\"") || raw.contains("openllmetry") {
            let end = raw.len().min(100);
            format!("OpenLLMetry OTLP: {}", &raw[..end])
        } else if payload.starts_with(b"POST /v1/traces") {
            "OpenLLMetry OTLP trace export".to_string()
        } else {
            format!("OpenLLMetry OTLP ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::OpenllmetryOtlp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openllmetry_otlp_trace() {
        let buf = b"POST /v1/traces HTTP/1.1\r\nHost: api.openllmetry.io\r\n";
        let r = dissect_openllmetry_otlp(None, None, 40000, 4318, buf);
        assert_eq!(r.protocol, Protocol::OpenllmetryOtlp);
        assert!(r.summary.contains("trace"));
    }

    #[test]
    fn test_openllmetry_otlp_llm() {
        let buf = b"{\"llm\":{\"model\":\"gpt-4\",\"prompt_tokens\":100}}";
        let r = dissect_openllmetry_otlp(None, None, 40000, 4318, buf);
        assert_eq!(r.protocol, Protocol::OpenllmetryOtlp);
        assert!(r.summary.contains("llm"));
    }
}
