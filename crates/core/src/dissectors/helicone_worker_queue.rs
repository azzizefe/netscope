use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_helicone_worker_queue(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 4 {
        "Helicone Worker Queue (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("\"requestId\"") || raw.contains("\"providerRequestId\"") {
            let end = raw.len().min(100);
            format!("Helicone Worker Queue: {}", &raw[..end])
        } else if raw.contains("/v1/log") || raw.contains("helicone") {
            format!("Helicone Worker Queue: {}", &raw[..raw.len().min(80)])
        } else {
            format!("Helicone Worker Queue ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::HeliconeWorkerQueue,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_helicone_worker_queue_log() {
        let buf = b"{\"requestId\":\"req_123\",\"providerRequestId\":\"prov_456\"}";
        let r = dissect_helicone_worker_queue(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::HeliconeWorkerQueue);
        assert!(r.summary.contains("requestId"));
    }

    #[test]
    fn test_helicone_worker_queue_malformed() {
        let buf = b"ab";
        let r = dissect_helicone_worker_queue(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
