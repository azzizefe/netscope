use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_amd_sev_snp_attest(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "AMD SEV-SNP Attestation (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("SEV") && (raw.contains("SNP") || raw.contains("attest")) {
            let end = raw.len().min(80);
            format!("AMD SEV-SNP Attestation: {}", &raw[..end])
        } else if raw.contains("ATTEST_REPORT") || raw.contains("TCB") || raw.contains("chip_id") {
            let end = raw.len().min(80);
            format!("AMD SEV-SNP Attestation: {}", &raw[..end])
        } else {
            format!("AMD SEV-SNP Attestation ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::AmdSevSnpAttest,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amd_sev_snp_attest_report() {
        let buf = b"SEV:SNP:ATTEST_REPORT:TCB=0xabc:chip_id=0xdef";
        let r = dissect_amd_sev_snp_attest(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::AmdSevSnpAttest);
        assert!(r.summary.contains("SEV-SNP"));
    }

    #[test]
    fn test_amd_sev_snp_malformed() {
        let buf = b"tiny";
        let r = dissect_amd_sev_snp_attest(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
