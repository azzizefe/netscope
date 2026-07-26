use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_ssh_pqc_kex(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 16 {
        "SSH PQC KEX (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("sntrup761") || raw.contains("sntrup761x25519") {
            let end = raw.len().min(80);
            format!("SSH PQC KEX: {}", &raw[..end])
        } else if raw.contains("kex_algorithms") && (raw.contains("ntrup") || raw.contains("mlkem")) {
            let end = raw.len().min(80);
            format!("SSH PQC KEX: {}", &raw[..end])
        } else if raw.contains("SSH_MSG_KEX_ECDH") && raw.contains("hybrid") {
            let end = raw.len().min(80);
            format!("SSH PQC KEX: {}", &raw[..end])
        } else {
            format!("SSH PQC KEX ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::SshPqcKex,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_pqc_sntrup761() {
        let buf = b"sntrup761x25519-sha512:pubkey_32B:ciphertext_1KB";
        let r = dissect_ssh_pqc_kex(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::SshPqcKex);
        assert!(r.summary.contains("KEX"));
    }

    #[test]
    fn test_ssh_pqc_kex_algorithms() {
        let buf = b"kex_algorithms:sntrup761x25519-sha512,mlkem768x25519-sha512";
        let r = dissect_ssh_pqc_kex(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::SshPqcKex);
    }

    #[test]
    fn test_ssh_pqc_hybrid_kex() {
        let buf = b"SSH_MSG_KEX_ECDH:hybrid:X25519+ML-KEM-768";
        let r = dissect_ssh_pqc_kex(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::SshPqcKex);
    }

    #[test]
    fn test_ssh_pqc_malformed() {
        let buf = b"tiny";
        let r = dissect_ssh_pqc_kex(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
