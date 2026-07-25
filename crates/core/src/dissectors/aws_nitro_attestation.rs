use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_aws_nitro_attestation(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "AWS Nitro Attestation (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("Nitro") && (raw.contains("attest") || raw.contains("enclave")) {
            let end = raw.len().min(80);
            format!("AWS Nitro Attestation: {}", &raw[..end])
        } else if raw.contains("PCR") && raw.contains("cert") && raw.contains("signature") {
            let end = raw.len().min(80);
            format!("AWS Nitro Attestation: {}", &raw[..end])
        } else {
            format!("AWS Nitro Attestation ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::AwsNitroAttestation,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_nitro_attest_report() {
        let buf = b"Nitro:enclave:attest:PCR0=0xabc:cert:signature";
        let r = dissect_aws_nitro_attestation(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::AwsNitroAttestation);
        assert!(r.summary.contains("Nitro Attestation"));
    }

    #[test]
    fn test_aws_nitro_attest_malformed() {
        let buf = b"tiny";
        let r = dissect_aws_nitro_attestation(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
