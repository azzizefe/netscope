use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_intel_tdx_attestation(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "Intel TDX Attestation (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("TDX") && (raw.contains("attest") || raw.contains("report")) {
            let end = raw.len().min(80);
            format!("Intel TDX Attestation: {}", &raw[..end])
        } else if raw.contains("TDQUOTE") || raw.contains("TEE_TCB") || raw.contains("seam") {
            let end = raw.len().min(80);
            format!("Intel TDX Attestation: {}", &raw[..end])
        } else {
            format!("Intel TDX Attestation ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::IntelTdxAttestation,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intel_tdx_attest_report() {
        let buf = b"TDX:attest:report:TDQUOTE=TEE_TCB:seam=0xabc";
        let r = dissect_intel_tdx_attestation(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::IntelTdxAttestation);
        assert!(r.summary.contains("TDX Attestation"));
    }

    #[test]
    fn test_intel_tdx_attest_malformed() {
        let buf = b"tiny";
        let r = dissect_intel_tdx_attestation(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
