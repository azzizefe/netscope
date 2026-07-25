use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_google_edge_tpu_compiler(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Google Edge TPU Compiler (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("edgetpu") || raw.contains("EdgeTPU") {
            let end = raw.len().min(80);
            format!("Google Edge TPU Compiler: {}", &raw[..end])
        } else if raw.contains("tpu_compile") || raw.contains("pipeline") {
            format!("Google Edge TPU Compiler: {}", &raw[..raw.len().min(80)])
        } else {
            format!("Google Edge TPU Compiler ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::GoogleEdgeTpuCompiler,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_google_edge_tpu_compiler_request() {
        let buf = b"EdgeTPU:compile:pipeline:model.tflite";
        let r = dissect_google_edge_tpu_compiler(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::GoogleEdgeTpuCompiler);
        assert!(r.summary.contains("EdgeTPU"));
    }

    #[test]
    fn test_google_edge_tpu_compiler_malformed() {
        let buf = b"short";
        let r = dissect_google_edge_tpu_compiler(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
