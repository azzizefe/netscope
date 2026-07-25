use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_fhe_google_shell(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 12 {
        "FHE Google SHELL (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("SHELL") || raw.contains("shell") && raw.contains("symmetric") {
            let end = raw.len().min(80);
            format!("FHE Google SHELL: {}", &raw[..end])
        } else if raw.contains("symmetric") && raw.contains("fhe") && raw.contains("key") {
            let end = raw.len().min(80);
            format!("FHE Google SHELL: {}", &raw[..end])
        } else {
            format!("FHE Google SHELL ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::FheGoogleShell,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fhe_google_shell_sym() {
        let buf = b"SHELL:symmetric:fhe:key=0xabcd:nonce=0x1234";
        let r = dissect_fhe_google_shell(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::FheGoogleShell);
        assert!(r.summary.contains("SHELL"));
    }

    #[test]
    fn test_fhe_google_shell_malformed() {
        let buf = b"short";
        let r = dissect_fhe_google_shell(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
