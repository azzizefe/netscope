use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_nemo_guardrails_http(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "NeMo Guardrails HTTP (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("nemo") || raw.contains("NeMo") || raw.contains("guardrails") {
            let end = raw.len().min(80);
            format!("NeMo Guardrails HTTP: {}", &raw[..end])
        } else if raw.contains("/v1/guardrails") || raw.contains("colang") {
            format!("NeMo Guardrails HTTP: {}", &raw[..raw.len().min(80)])
        } else {
            format!("NeMo Guardrails HTTP ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::NemoGuardrailsHttp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nemo_guardrails_http_request() {
        let buf = b"POST /v1/guardrails/validate HTTP/1.1\r\nHost: nemo.example.com\r\n";
        let r = dissect_nemo_guardrails_http(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::NemoGuardrailsHttp);
        assert!(r.summary.contains("guardrails"));
    }

    #[test]
    fn test_nemo_guardrails_http_malformed() {
        let buf = b"short";
        let r = dissect_nemo_guardrails_http(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
