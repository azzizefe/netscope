use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_mlflow_gateway_stream(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "MLflow Gateway Stream (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("mlflow") && raw.contains("gateway") && raw.contains("route") {
            let end = raw.len().min(80);
            format!("MLflow Gateway Stream: {}", &raw[..end])
        } else if raw.contains("endpoint") && raw.contains("mlflow") && raw.contains("data") {
            let end = raw.len().min(80);
            format!("MLflow Gateway Stream: {}", &raw[..end])
        } else {
            format!("MLflow Gateway Stream ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::MlflowGatewayStream,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlflow_gateway_stream_route() {
        let buf = b"data: {\"mlflow\":true,\"gateway\":{\"route\":\"chat\"},\"endpoint\":\"gpt4\"}";
        let r = dissect_mlflow_gateway_stream(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::MlflowGatewayStream);
        assert!(r.summary.contains("MLflow Gateway"));
    }

    #[test]
    fn test_mlflow_gateway_stream_malformed() {
        let buf = b"bad";
        let r = dissect_mlflow_gateway_stream(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
