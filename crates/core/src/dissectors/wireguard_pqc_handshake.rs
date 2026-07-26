use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_wireguard_pqc_handshake(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 32 {
        "WireGuard PQC Handshake (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("WG-PQC") || raw.contains("noise_pqc") {
            let end = raw.len().min(80);
            format!("WireGuard PQC Handshake: {}", &raw[..end])
        } else if raw.contains("KEM") && raw.contains("Curve25519") {
            let end = raw.len().min(80);
            format!("WireGuard PQC Handshake: {}", &raw[..end])
        } else if raw.contains("handshake_init") && raw.contains("ML-KEM") {
            let end = raw.len().min(80);
            format!("WireGuard PQC Handshake: {}", &raw[..end])
        } else {
            format!("WireGuard PQC Handshake ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::WireguardPqcHandshake,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wg_pqc_handshake_tag() {
        let buf = b"WG-PQC:noise_pqc:Curve25519+ML-KEM-768";
        let r = dissect_wireguard_pqc_handshake(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::WireguardPqcHandshake);
        assert!(r.summary.contains("Handshake"));
    }

    #[test]
    fn test_wg_pqc_handshake_kem() {
        let buf = b"KEM:ML-KEM-768:Curve25519:initiator_pubkey_32_bytes";
        let r = dissect_wireguard_pqc_handshake(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::WireguardPqcHandshake);
    }

    #[test]
    fn test_wg_pqc_handshake_init() {
        let buf = b"handshake_init:ML-KEM-768:ciphertext_1KB_payload";
        let r = dissect_wireguard_pqc_handshake(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::WireguardPqcHandshake);
    }

    #[test]
    fn test_wg_pqc_handshake_malformed() {
        let buf = b"too short";
        let r = dissect_wireguard_pqc_handshake(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
