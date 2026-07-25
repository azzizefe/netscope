use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_nebula_pq_handshake(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Nebula PQ Handshake (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("Nebula") && (raw.contains("PQ") || raw.contains("handshake")) {
            let end = raw.len().min(80);
            format!("Nebula PQ Handshake: {}", &raw[..end])
        } else if raw.contains("nebula_pq") || raw.contains("stage1") && raw.contains("kem") {
            let end = raw.len().min(80);
            format!("Nebula PQ Handshake: {}", &raw[..end])
        } else {
            format!("Nebula PQ Handshake ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::NebulaPqHandshake,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nebula_pq_handshake_stage1() {
        let buf = b"Nebula:PQ:handshake:stage1:kem=FrodoKEM:epk=0xabc";
        let r = dissect_nebula_pq_handshake(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::NebulaPqHandshake);
        assert!(r.summary.contains("PQ Handshake"));
    }

    #[test]
    fn test_nebula_pq_handshake_malformed() {
        let buf = b"short";
        let r = dissect_nebula_pq_handshake(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
