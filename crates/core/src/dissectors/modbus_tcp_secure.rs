use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_modbus_tcp_secure(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "Modbus/TCP Secure (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("Modbus") && raw.contains("TLS") {
            let end = raw.len().min(80);
            format!("Modbus/TCP Secure: {}", &raw[..end])
        } else if raw.contains("modbus") && (raw.contains("secure") || raw.contains("tls")) {
            let end = raw.len().min(80);
            format!("Modbus/TCP Secure: {}", &raw[..end])
        } else {
            format!("Modbus/TCP Secure ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::ModbusTcpSecure,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modbus_tcp_secure_session() {
        let buf = b"Modbus:TLS:secure:read_holding=100";
        let r = dissect_modbus_tcp_secure(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::ModbusTcpSecure);
        assert!(r.summary.contains("Modbus"));
    }

    #[test]
    fn test_modbus_tcp_secure_malformed() {
        let buf = b"short";
        let r = dissect_modbus_tcp_secure(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
