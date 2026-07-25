use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_ipsec_ikev2_frodo(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "IKEv2 FrodoKEM (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("IKEv2") && (raw.contains("Frodo") || raw.contains("frodo")) {
            let end = raw.len().min(80);
            format!("IKEv2 FrodoKEM: {}", &raw[..end])
        } else if raw.contains("FrodoKEM") && (raw.contains("SA") || raw.contains("key_exch")) {
            let end = raw.len().min(80);
            format!("IKEv2 FrodoKEM: {}", &raw[..end])
        } else {
            format!("IKEv2 FrodoKEM ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::IpsecIkev2Frodo,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipsec_ikev2_frodo_exchange() {
        let buf = b"IKEv2:FrodoKEM-1344-AES:SA:key_exch=0x123";
        let r = dissect_ipsec_ikev2_frodo(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::IpsecIkev2Frodo);
        assert!(r.summary.contains("FrodoKEM"));
    }

    #[test]
    fn test_ipsec_ikev2_frodo_malformed() {
        let buf = b"tiny";
        let r = dissect_ipsec_ikev2_frodo(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
