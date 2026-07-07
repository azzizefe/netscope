use std::net::IpAddr;

use crate::models::Protocol;

use super::{first_text_line, truncate, DissectedResult};

/// Dissect an SSH segment (TCP 22). The connection opens with a plaintext
/// version banner (`SSH-2.0-OpenSSH_8.9`); everything after is encrypted.
pub fn dissect_ssh(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.starts_with(b"SSH-") {
        format!("SSH — {}", truncate(&first_text_line(payload), 40))
    } else {
        format!("SSH — encrypted, {} bytes", payload.len())
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Ssh,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_is_shown() {
        let r = dissect_ssh(None, None, 50000, 22, b"SSH-2.0-OpenSSH_8.9p1\r\n");
        assert_eq!(r.protocol, Protocol::Ssh);
        assert_eq!(r.summary, "SSH — SSH-2.0-OpenSSH_8.9p1");
    }

    #[test]
    fn encrypted_payload_reports_size() {
        let r = dissect_ssh(None, None, 22, 50000, &[0x14; 64]);
        assert_eq!(r.summary, "SSH — encrypted, 64 bytes");
    }
}
