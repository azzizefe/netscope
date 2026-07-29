use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

fn parse_sct_version(payload: &[u8]) -> u8 {
    payload.first().copied().unwrap_or(0)
}

fn count_sct_entries(payload: &[u8]) -> usize {
    if payload.len() < 3 {
        return 0;
    }
    let count = u16::from_be_bytes([payload[1], payload[2]]);
    count as usize
}

pub fn dissect_tls_cert_transparency_v3(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let sct_version = parse_sct_version(payload);
    let entry_count = count_sct_entries(payload);

    let record_count = crate::dissectors::tls::drain_pqc_store().len();

    let summary = if sct_version > 0 {
        format!(
            "Certificate Transparency v3: SCT version {}, {} entries (from {} TLS records) — PQC-aware SCT parsing {}",
            sct_version,
            entry_count,
            record_count,
            if entry_count > 0 { "active" } else { "idle" },
        )
    } else {
        format!(
            "Certificate Transparency v3: no SCT data ({} TLS records tracked)",
            record_count,
        )
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TlsCertTransparencyV3,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sct_version_zero() {
        assert_eq!(parse_sct_version(&[]), 0);
        assert_eq!(parse_sct_version(&[0x00]), 0);
    }

    #[test]
    fn parse_sct_version_nonzero() {
        assert_eq!(parse_sct_version(&[0x01, 0x00, 0x01]), 1);
        assert_eq!(parse_sct_version(&[0xFF, 0x00, 0x00]), 255);
    }

    #[test]
    fn count_sct_entries_empty() {
        assert_eq!(count_sct_entries(&[]), 0);
        assert_eq!(count_sct_entries(&[0x00]), 0);
        assert_eq!(count_sct_entries(&[0x00, 0x00]), 0);
    }

    #[test]
    fn count_sct_entries_some() {
        assert_eq!(count_sct_entries(&[0x00, 0x00, 0x05]), 5);
        assert_eq!(count_sct_entries(&[0x00, 0x01, 0x00]), 256);
    }

    #[test]
    fn dissect_no_sct_data() {
        crate::dissectors::tls::clear_tls_sessions();
        let result = dissect_tls_cert_transparency_v3(None, None, 0, 0, &[]);
        assert_eq!(result.protocol, Protocol::TlsCertTransparencyV3);
        assert!(result.summary.contains("no SCT data"));
    }

    #[test]
    fn dissect_with_sct_data() {
        crate::dissectors::tls::clear_tls_sessions();
        let payload = [0x01, 0x00, 0x02]; // version=1, 2 entries
        let result = dissect_tls_cert_transparency_v3(None, None, 443, 54321, &payload);
        assert_eq!(result.protocol, Protocol::TlsCertTransparencyV3);
        assert!(result.summary.contains("SCT version 1"));
        assert!(result.summary.contains("2 entries"));
    }

    #[test]
    fn dissect_with_src_dst_addrs() {
        crate::dissectors::tls::clear_tls_sessions();
        let src = "10.0.0.1".parse::<IpAddr>().ok();
        let dst = "192.168.1.1".parse::<IpAddr>().ok();
        let result = dissect_tls_cert_transparency_v3(src, dst, 443, 54321, &[0x00]);
        assert_eq!(result.src_addr, src);
        assert_eq!(result.dst_addr, dst);
        assert_eq!(result.src_port, Some(443));
        assert_eq!(result.dst_port, Some(54321));
    }
}
