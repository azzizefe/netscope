use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_onnx_runtime_execution_provider(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "ONNX Runtime EP (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("onnxruntime") || raw.contains("OrtEP") {
            let end = raw.len().min(80);
            format!("ONNX Runtime EP: {}", &raw[..end])
        } else if raw.contains("execution_provider") || raw.contains("session_options") {
            format!("ONNX Runtime EP: {}", &raw[..raw.len().min(80)])
        } else {
            format!("ONNX Runtime EP ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::OnnxRuntimeExecutionProvider,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_onnx_runtime_ep_bridge() {
        let buf = b"onnxruntime:OrtEP:create_session:CPU";
        let r = dissect_onnx_runtime_execution_provider(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::OnnxRuntimeExecutionProvider);
        assert!(r.summary.contains("onnxruntime"));
    }

    #[test]
    fn test_onnx_runtime_ep_malformed() {
        let buf = b"short";
        let r = dissect_onnx_runtime_execution_provider(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
