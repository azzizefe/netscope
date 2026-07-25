use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_intel_sgx_dcap_quote(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "Intel SGX DCAP Quote (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("SGX") && (raw.contains("DCAP") || raw.contains("quote")) {
            let end = raw.len().min(80);
            format!("Intel SGX DCAP Quote: {}", &raw[..end])
        } else if raw.contains("MRENCLAVE") || raw.contains("MRSIGNER") || raw.contains("report") {
            let end = raw.len().min(80);
            format!("Intel SGX DCAP Quote: {}", &raw[..end])
        } else {
            format!("Intel SGX DCAP Quote ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::IntelSgxDcapQuote,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intel_sgx_dcap_quote_report() {
        let buf = b"SGX:DCAP:quote:MRENCLAVE=0xabc:MRSIGNER=0xdef";
        let r = dissect_intel_sgx_dcap_quote(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::IntelSgxDcapQuote);
        assert!(r.summary.contains("SGX DCAP"));
    }

    #[test]
    fn test_intel_sgx_dcap_malformed() {
        let buf = b"tiny";
        let r = dissect_intel_sgx_dcap_quote(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
