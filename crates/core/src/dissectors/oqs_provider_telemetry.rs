use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_oqs_provider_telemetry(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "OQS Provider Telemetry (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("OQS") && (raw.contains("provider") || raw.contains("telemetry")) {
            let end = raw.len().min(80);
            format!("OQS Provider Telemetry: {}", &raw[..end])
        } else if raw.contains("algorithm_bench") && raw.contains("ops_per_sec") {
            let end = raw.len().min(80);
            format!("OQS Provider Telemetry: {}", &raw[..end])
        } else if raw.contains("provider_version") || raw.contains("oqs_version") {
            let end = raw.len().min(80);
            format!("OQS Provider Telemetry: {}", &raw[..end])
        } else {
            format!("OQS Provider Telemetry ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::OqsProviderTelemetry,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oqs_telemetry_provider() {
        let buf = b"OQS:provider:oqsprovider-0.6.0:algorithms=72";
        let r = dissect_oqs_provider_telemetry(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::OqsProviderTelemetry);
        assert!(r.summary.contains("Telemetry"));
    }

    #[test]
    fn test_oqs_telemetry_bench() {
        let buf = b"algorithm_bench:ML-KEM-768:enc=45000ops/sec:dec=42000ops/sec";
        let r = dissect_oqs_provider_telemetry(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::OqsProviderTelemetry);
    }

    #[test]
    fn test_oqs_telemetry_version() {
        let buf = b"oqs_version:0.10.0:provider_version:0.6.0";
        let r = dissect_oqs_provider_telemetry(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::OqsProviderTelemetry);
    }

    #[test]
    fn test_oqs_telemetry_malformed() {
        let buf = b"short";
        let r = dissect_oqs_provider_telemetry(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
