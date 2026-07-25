use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_guardrails_ai_validator(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Guardrails AI Validator (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("guardrails") || raw.contains("validators") {
            let end = raw.len().min(80);
            format!("Guardrails AI Validator: {}", &raw[..end])
        } else if raw.contains("output_check") || raw.contains("validation_result") {
            format!("Guardrails AI Validator: {}", &raw[..raw.len().min(80)])
        } else {
            format!("Guardrails AI Validator ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::GuardrailsAiValidator,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guardrails_ai_validator_check() {
        let buf = b"{\"guardrails\":\"output_check\",\"validators\":[\"no_pii\"]}";
        let r = dissect_guardrails_ai_validator(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::GuardrailsAiValidator);
        assert!(r.summary.contains("guardrails"));
    }

    #[test]
    fn test_guardrails_ai_validator_malformed() {
        let buf = b"short";
        let r = dissect_guardrails_ai_validator(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
