use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_tpm2_remote_attestation(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "TPM 2.0 Remote Attestation (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("TPM") && (raw.contains("attest") || raw.contains("DICE")) {
            let end = raw.len().min(80);
            format!("TPM 2.0 Remote Attestation: {}", &raw[..end])
        } else if raw.contains("TPMS_ATTEST") || raw.contains("quote") && raw.contains("pcr") {
            let end = raw.len().min(80);
            format!("TPM 2.0 Remote Attestation: {}", &raw[..end])
        } else {
            format!("TPM 2.0 Remote Attestation ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Tpm2RemoteAttestation,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tpm2_remote_attest_pcr() {
        let buf = b"TPM:attest:DICE:TPMS_ATTEST:quote:pcr=15";
        let r = dissect_tpm2_remote_attestation(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::Tpm2RemoteAttestation);
        assert!(r.summary.contains("TPM 2.0"));
    }

    #[test]
    fn test_tpm2_remote_attest_malformed() {
        let buf = b"tiny";
        let r = dissect_tpm2_remote_attestation(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
