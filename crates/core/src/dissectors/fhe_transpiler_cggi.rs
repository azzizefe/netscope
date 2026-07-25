use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_fhe_transpiler_cggi(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "FHE Transpiler CGGI (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("CGGI") || raw.contains("cggi") && raw.contains("transpiler") {
            let end = raw.len().min(80);
            format!("FHE Transpiler CGGI: {}", &raw[..end])
        } else if raw.contains("circuit") && raw.contains("TFHE") && raw.contains("gate") {
            let end = raw.len().min(80);
            format!("FHE Transpiler CGGI: {}", &raw[..end])
        } else {
            format!("FHE Transpiler CGGI ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::FheTranspilerCggi,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fhe_transpiler_cggi_bridge() {
        let buf = b"CGGI:transpiler:circuit:TFHE:gate=XNOR";
        let r = dissect_fhe_transpiler_cggi(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::FheTranspilerCggi);
        assert!(r.summary.contains("CGGI"));
    }

    #[test]
    fn test_fhe_transpiler_cggi_malformed() {
        let buf = b"short";
        let r = dissect_fhe_transpiler_cggi(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
