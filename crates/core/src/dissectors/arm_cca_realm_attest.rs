use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_arm_cca_realm_attest(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "Arm CCA Realm Attestation (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("CCA") && (raw.contains("realm") || raw.contains("attest")) {
            let end = raw.len().min(80);
            format!("Arm CCA Realm Attestation: {}", &raw[..end])
        } else if raw.contains("RPV") || raw.contains("CCA_token") || raw.contains("platform") {
            let end = raw.len().min(80);
            format!("Arm CCA Realm Attestation: {}", &raw[..end])
        } else {
            format!("Arm CCA Realm Attestation ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::ArmCcaRealmAttest,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arm_cca_realm_token() {
        let buf = b"CCA:realm:attest:RPV=0xabc:CCA_token=platform";
        let r = dissect_arm_cca_realm_attest(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::ArmCcaRealmAttest);
        assert!(r.summary.contains("CCA Realm"));
    }

    #[test]
    fn test_arm_cca_realm_malformed() {
        let buf = b"tiny";
        let r = dissect_arm_cca_realm_attest(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
