use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_tls_pqc_migration_signal(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "TLS PQC Migration Signal (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("pqc_migration") || raw.contains("PQC_READY") {
            let end = raw.len().min(80);
            format!("TLS PQC Migration Signal: {}", &raw[..end])
        } else if raw.contains("capability_advert") && raw.contains("PQ") {
            let end = raw.len().min(80);
            format!("TLS PQC Migration Signal: {}", &raw[..end])
        } else if raw.contains("fallback") && raw.contains("classical") {
            let end = raw.len().min(80);
            format!("TLS PQC Migration Signal: {}", &raw[..end])
        } else {
            format!("TLS PQC Migration Signal ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TlsPqcMigrationSignal,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_signal_ready() {
        let buf = b"pqc_migration:PQC_READY:ML-KEM-768,ML-DSA-65";
        let r = dissect_tls_pqc_migration_signal(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::TlsPqcMigrationSignal);
        assert!(r.summary.contains("Migration"));
    }

    #[test]
    fn test_migration_signal_capability() {
        let buf = b"capability_advert:PQ:Kyber1024,Dilithium5";
        let r = dissect_tls_pqc_migration_signal(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::TlsPqcMigrationSignal);
    }

    #[test]
    fn test_migration_signal_fallback() {
        let buf = b"fallback:classical:X25519:ECDSA-P256";
        let r = dissect_tls_pqc_migration_signal(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::TlsPqcMigrationSignal);
    }

    #[test]
    fn test_migration_signal_malformed() {
        let buf = b"ab";
        let r = dissect_tls_pqc_migration_signal(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
