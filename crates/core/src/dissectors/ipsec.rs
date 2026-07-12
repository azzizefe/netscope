use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an IPsec ESP datagram (IP protocol 50).
///
/// ESP (Encapsulating Security Payload) is the workhorse of IPsec VPNs: it
/// encrypts the payload and is identified on the wire only by its SPI (Security
/// Parameters Index) and a monotonic sequence number, both in the clear at the
/// front. Tracking the SPI lets you tell one tunnel from another and follow a
/// single security association; the rest is ciphertext.
pub fn dissect_esp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    let base = DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Esp,
        summary: String::new(),
    };

    if payload.len() < 8 {
        return DissectedResult {
            summary: "ESP (IPsec, partial)".into(),
            ..base
        };
    }
    let spi = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let seq = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    DissectedResult {
        summary: format!("ESP (IPsec) — SPI 0x{spi:08x}, seq {seq}"),
        ..base
    }
}

/// Dissect an IPsec AH datagram (IP protocol 51).
///
/// AH (Authentication Header) authenticates a packet without encrypting it:
/// next-header(1), payload-len(1), reserved(2), SPI(4), sequence(4), then the
/// integrity check value. We report the SPI, sequence and the protocol AH is
/// protecting.
pub fn dissect_ah(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    payload: &[u8],
) -> DissectedResult {
    let base = DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: None,
        dst_port: None,
        protocol: Protocol::Ah,
        summary: String::new(),
    };

    if payload.len() < 12 {
        return DissectedResult {
            summary: "AH (IPsec, partial)".into(),
            ..base
        };
    }
    let next_header = payload[0];
    let spi = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let seq = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
    DissectedResult {
        summary: format!(
            "AH (IPsec) — SPI 0x{spi:08x}, seq {seq}, protects {}",
            next_header_name(next_header)
        ),
        ..base
    }
}

fn next_header_name(p: u8) -> String {
    match p {
        1 => "ICMP".into(),
        6 => "TCP".into(),
        17 => "UDP".into(),
        50 => "ESP".into(),
        58 => "ICMPv6".into(),
        other => format!("IP proto {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn esp_spi_and_seq() {
        let mut p = Vec::new();
        p.extend_from_slice(&0xdead_beefu32.to_be_bytes());
        p.extend_from_slice(&42u32.to_be_bytes());
        p.extend_from_slice(&[0u8; 16]);
        let r = dissect_esp(None, None, &p);
        assert_eq!(r.protocol, Protocol::Esp);
        assert_eq!(r.summary, "ESP (IPsec) — SPI 0xdeadbeef, seq 42");
    }

    #[test]
    fn ah_reports_protected_protocol() {
        let mut p = vec![6, 4, 0, 0]; // next-header TCP, len, reserved
        p.extend_from_slice(&0x11223344u32.to_be_bytes()); // SPI
        p.extend_from_slice(&7u32.to_be_bytes()); // seq
        p.extend_from_slice(&[0u8; 12]); // ICV
        let r = dissect_ah(None, None, &p);
        assert_eq!(r.protocol, Protocol::Ah);
        assert_eq!(
            r.summary,
            "AH (IPsec) — SPI 0x11223344, seq 7, protects TCP"
        );
    }

    #[test]
    fn esp_partial_is_safe() {
        let r = dissect_esp(None, None, &[0, 1, 2]);
        assert!(r.summary.contains("partial"));
    }
}
