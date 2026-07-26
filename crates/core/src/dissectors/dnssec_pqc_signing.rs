use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_dnssec_pqc_signing(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 16 {
        "DNSSEC PQC Signing (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("RRSIG") && (raw.contains("Falcon") || raw.contains("Dilithium")) {
            let end = raw.len().min(80);
            format!("DNSSEC PQC Signing: {}", &raw[..end])
        } else if raw.contains("DNSKEY") && raw.contains("ML-DSA") {
            let end = raw.len().min(80);
            format!("DNSSEC PQC Signing: {}", &raw[..end])
        } else if raw.contains("algorithm") && (raw.contains("falcon") || raw.contains("slh_dsa")) {
            let end = raw.len().min(80);
            format!("DNSSEC PQC Signing: {}", &raw[..end])
        } else {
            format!("DNSSEC PQC Signing ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::DnssecPqcSigning,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dnssec_pqc_rrsig_falcon() {
        let buf = b"RRSIG:Falcon-512:example.com:signature_value_raw";
        let r = dissect_dnssec_pqc_signing(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::DnssecPqcSigning);
        assert!(r.summary.contains("Signing"));
    }

    #[test]
    fn test_dnssec_pqc_dnskey() {
        let buf = b"DNSKEY:ML-DSA-65:zone_signing_key:flags=256";
        let r = dissect_dnssec_pqc_signing(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::DnssecPqcSigning);
    }

    #[test]
    fn test_dnssec_pqc_algorithm() {
        let buf = b"algorithm:falcon-512:key_tag=12345";
        let r = dissect_dnssec_pqc_signing(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::DnssecPqcSigning);
    }

    #[test]
    fn test_dnssec_pqc_malformed() {
        let buf = b"too short";
        let r = dissect_dnssec_pqc_signing(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
