use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_azure_ai_content_safety(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Azure AI Content Safety (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("contentsafety") || raw.contains("ContentSafety") {
            let end = raw.len().min(80);
            format!("Azure AI Content Safety: {}", &raw[..end])
        } else if raw.contains("severity") || raw.contains("categoriesAnalysis") {
            format!("Azure AI Content Safety: {}", &raw[..raw.len().min(80)])
        } else {
            format!("Azure AI Content Safety ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::AzureAiContentSafety,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_azure_ai_content_safety_eval() {
        let buf = b"{\"contentsafety\":true,\"severity\":\"medium\",\"categoriesAnalysis\":[]}";
        let r = dissect_azure_ai_content_safety(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::AzureAiContentSafety);
        assert!(r.summary.contains("contentsafety"));
    }

    #[test]
    fn test_azure_ai_content_safety_malformed() {
        let buf = b"short";
        let r = dissect_azure_ai_content_safety(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
