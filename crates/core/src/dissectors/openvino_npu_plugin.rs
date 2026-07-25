use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_openvino_npu_plugin(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "OpenVINO NPU Plugin (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("openvino") || raw.contains("OpenVINO") {
            let end = raw.len().min(80);
            format!("OpenVINO NPU Plugin: {}", &raw[..end])
        } else if raw.contains("npu_plugin") || raw.contains("inference_request") {
            format!("OpenVINO NPU Plugin: {}", &raw[..raw.len().min(80)])
        } else {
            format!("OpenVINO NPU Plugin ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::OpenvinoNpuPlugin,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openvino_npu_plugin_request() {
        let buf = b"OpenVINO:npu_plugin:infer:model.xml";
        let r = dissect_openvino_npu_plugin(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::OpenvinoNpuPlugin);
        assert!(r.summary.contains("OpenVINO"));
    }

    #[test]
    fn test_openvino_npu_plugin_malformed() {
        let buf = b"short";
        let r = dissect_openvino_npu_plugin(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
