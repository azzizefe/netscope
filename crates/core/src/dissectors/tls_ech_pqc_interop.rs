use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

fn parse_ech_config_version(payload: &[u8]) -> u16 {
    if payload.len() < 4 {
        return 0;
    }
    u16::from_be_bytes([payload[0], payload[1]])
}

fn has_pqc_kem_ids(payload: &[u8]) -> bool {
    let kem_ids = [0x0039u16, 0x003A, 0x003B, 0x00FE, 0x00FF];
    payload.windows(2).any(|w| {
        let val = u16::from_be_bytes([w[0], w[1]]);
        kem_ids.contains(&val)
    })
}

pub fn dissect_tls_ech_pqc_interop(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let ech_version = parse_ech_config_version(payload);
    let ech_pqc_aware = has_pqc_kem_ids(payload);

    let records = crate::dissectors::tls::drain_pqc_store();
    let pqc_count = records.iter().filter(|r| r.used_pqc()).count();
    let ech_compatible = records
        .iter()
        .any(|r| r.client_hello_size > 0 && r.server_hello_size > 0 && r.used_pqc());

    let compatibility = if ech_pqc_aware || ech_compatible {
        "PQC-compatible ECH"
    } else {
        "ECH without PQC"
    };

    let summary = if ech_version > 0 {
        format!(
            "ECH + PQC Interop: ECH v{}, PQC-aware KEM IDs {}, {} PQ handshakes — {}",
            ech_version,
            if ech_pqc_aware { "present" } else { "absent" },
            pqc_count,
            compatibility,
        )
    } else {
        format!(
            "ECH + PQC Interop: no ECH payload ({} TLS sessions, {} PQC) — {}",
            records.len(),
            pqc_count,
            compatibility,
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TlsEchPqcInterop,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ech_config_version_short() {
        assert_eq!(parse_ech_config_version(&[]), 0);
        assert_eq!(parse_ech_config_version(&[0x00, 0x01, 0x02]), 0);
    }

    #[test]
    fn parse_ech_config_version_valid() {
        assert_eq!(parse_ech_config_version(&[0x00, 0x01, 0x00, 0x00, 0xFF]), 1);
        assert_eq!(parse_ech_config_version(&[0xFE, 0xFE, 0x00, 0x00]), 0xFEFE);
    }

    #[test]
    fn has_pqc_kem_ids_present() {
        let data = [0x00, 0x39, 0x00, 0x3A, 0x00, 0x3B];
        assert!(has_pqc_kem_ids(&data));
    }

    #[test]
    fn has_pqc_kem_ids_absent() {
        assert!(!has_pqc_kem_ids(&[0x00, 0x17, 0x00, 0x1D]));
    }

    #[test]
    fn has_pqc_kem_ids_empty() {
        assert!(!has_pqc_kem_ids(&[]));
    }

    #[test]
    fn dissect_no_ech_payload() {
        crate::dissectors::tls::clear_tls_sessions();
        let result = dissect_tls_ech_pqc_interop(None, None, 443, 54321, &[]);
        assert_eq!(result.protocol, Protocol::TlsEchPqcInterop);
        assert!(result.summary.contains("no ECH payload"));
    }

    #[test]
    fn dissect_with_ech_pqc_kem() {
        crate::dissectors::tls::clear_tls_sessions();
        let payload = [0x00, 0x01, 0x00, 0x39]; // version=1, KEM 0x0039
        let result = dissect_tls_ech_pqc_interop(None, None, 443, 54321, &payload);
        assert_eq!(result.protocol, Protocol::TlsEchPqcInterop);
        assert!(result.summary.contains("ECH v1"));
        assert!(result.summary.contains("PQC-aware KEM IDs present"));
    }

    #[test]
    fn dissect_with_ech_no_pqc() {
        crate::dissectors::tls::clear_tls_sessions();
        let payload = [0x00, 0x01, 0x00, 0x17]; // version=1, X25519 (not PQC)
        let result = dissect_tls_ech_pqc_interop(None, None, 443, 54321, &payload);
        assert!(result.summary.contains("PQC-aware KEM IDs absent"));
    }
}
