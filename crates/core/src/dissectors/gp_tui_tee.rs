use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_gp_tui_tee(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "GP TUI TEE (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("GP_TUI") || raw.contains("tui") && raw.contains("TEE") {
            let end = raw.len().min(80);
            format!("GP TUI TEE: {}", &raw[..end])
        } else if raw.contains("display") && raw.contains("input") && raw.contains("secure") {
            let end = raw.len().min(80);
            format!("GP TUI TEE: {}", &raw[..end])
        } else {
            format!("GP TUI TEE ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::GpTuiTee,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gp_tui_tee_display() {
        let buf = b"GP_TUI:TEE:secure:display:input:session=0xabc";
        let r = dissect_gp_tui_tee(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::GpTuiTee);
        assert!(r.summary.contains("GP TUI"));
    }

    #[test]
    fn test_gp_tui_tee_malformed() {
        let buf = b"short";
        let r = dissect_gp_tui_tee(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
