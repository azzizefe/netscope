use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_pir_sealpir(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "PIR SealPIR (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("SealPIR") || raw.contains("sealpir") || raw.contains("PIR") && raw.contains("query") {
            let end = raw.len().min(80);
            format!("PIR SealPIR: {}", &raw[..end])
        } else if raw.contains("ciphertext") && raw.contains("index") && raw.contains("database") {
            let end = raw.len().min(80);
            format!("PIR SealPIR: {}", &raw[..end])
        } else {
            format!("PIR SealPIR ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::PirSealpir,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pir_sealpir_query() {
        let buf = b"SealPIR:query:index=42:ciphertext=0xabcd";
        let r = dissect_pir_sealpir(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::PirSealpir);
        assert!(r.summary.contains("SealPIR"));
    }

    #[test]
    fn test_pir_sealpir_malformed() {
        let buf = b"short";
        let r = dissect_pir_sealpir(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
