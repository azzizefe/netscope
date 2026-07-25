use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_keyence_cv_x_ftp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Keyence CV-X FTP (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("Keyence") || raw.contains("CV-X") || raw.contains("keyence") {
            let end = raw.len().min(80);
            format!("Keyence CV-X FTP: {}", &raw[..end])
        } else if raw.contains("image_transfer") || raw.contains(".bmp") || raw.contains(".jpg") {
            format!("Keyence CV-X FTP: {}", &raw[..raw.len().min(80)])
        } else {
            format!("Keyence CV-X FTP ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::KeyenceCvXFtp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyence_cv_x_ftp_transfer() {
        let buf = b"Keyence CV-X:image_transfer:image_001.bmp";
        let r = dissect_keyence_cv_x_ftp(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::KeyenceCvXFtp);
        assert!(r.summary.contains("Keyence"));
    }

    #[test]
    fn test_keyence_cv_x_ftp_malformed() {
        let buf = b"short";
        let r = dissect_keyence_cv_x_ftp(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
