use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_coreml_model_compile_rpc(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Core ML Compile RPC (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("ANED") || raw.contains("ane_compile") {
            let end = raw.len().min(80);
            format!("Core ML Compile RPC: {}", &raw[..end])
        } else if raw.contains("milmodel") || raw.contains("espresso") {
            format!("Core ML Compile RPC: {}", &raw[..raw.len().min(80)])
        } else {
            format!("Core ML Compile RPC ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::CoremlModelCompileRpc,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coreml_compile_rpc_aned() {
        let buf = b"ANED:compile:milmodel://model.mlmodelc";
        let r = dissect_coreml_model_compile_rpc(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::CoremlModelCompileRpc);
        assert!(r.summary.contains("ANED"));
    }

    #[test]
    fn test_coreml_compile_rpc_malformed() {
        let buf = b"short";
        let r = dissect_coreml_model_compile_rpc(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
