use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_detnet_service_layer(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "DetNet Service Layer (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("DetNet") || raw.contains("detnet") || raw.contains("service_layer") {
            let end = raw.len().min(80);
            format!("DetNet Service Layer: {}", &raw[..end])
        } else if raw.contains("app_flow") || raw.contains("tspec") || raw.contains("path") {
            format!("DetNet Service Layer: {}", &raw[..raw.len().min(80)])
        } else {
            format!("DetNet Service Layer ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::DetnetServiceLayer,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detnet_service_layer_app_flow() {
        let buf = b"DetNet:service_layer:app_flow:tspec";
        let r = dissect_detnet_service_layer(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::DetnetServiceLayer);
        assert!(r.summary.contains("DetNet"));
    }

    #[test]
    fn test_detnet_service_layer_malformed() {
        let buf = b"short";
        let r = dissect_detnet_service_layer(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
