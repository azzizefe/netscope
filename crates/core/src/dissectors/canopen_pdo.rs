use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

/// PDO communication parameter byte.
fn pdo_type_name(t: u8) -> &'static str {
    match t & 0xF0 {
        0x00 => "Receives PDO1",
        0x10 => "Receives PDO2",
        0x20 => "Receives PDO3",
        0x30 => "Receives PDO4",
        0x40 => "Transmits PDO1",
        0x50 => "Transmits PDO2",
        0x60 => "Transmits PDO3",
        0x70 => "Transmits PDO4",
        _    => "Unknown PDO",
    }
}

pub fn dissect_canopen_pdo(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 2 {
        "CANopen PDO (malformed)".into()
    } else {
        let pdo_type = pdo_type_name(payload[0]);
        let data_len = payload.len() - 1;
        let data_bytes = if data_len > 8 { 8 } else { data_len };
        let mut hex = String::with_capacity(data_bytes * 3);
        for &b in payload[1..=data_bytes].iter() {
            hex.push_str(&format!("{b:02X} "));
        }
        format!("CANopen PDO: {pdo_type} data={data_len}B [{hex}]")
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::CanopenPdo,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdo_receive() {
        let buf = &[0x00, 0x01, 0x02, 0x03];
        let r = dissect_canopen_pdo(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::CanopenPdo);
        assert!(r.summary.contains("Receives PDO1"));
        assert!(r.summary.contains("3B"));
    }

    #[test]
    fn pdo_transmit() {
        let buf = &[0x51, 0xAA, 0xBB];
        let r = dissect_canopen_pdo(None, None, 0, 0, buf);
        assert!(r.summary.contains("Transmits PDO2"));
    }

    #[test]
    fn pdo_malformed() {
        let buf = &[0x00];
        let r = dissect_canopen_pdo(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
