use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a WireGuard packet (UDP 51820 by default).
///
/// WireGuard is the modern, minimal VPN. Its framing is tiny: the first byte is
/// the message type (1 handshake initiation, 2 handshake response, 3 cookie
/// reply, 4 transport data), followed by three reserved zero bytes. Handshake
/// packets have fixed sizes (148 and 92 bytes); transport-data packets carry a
/// receiver index and counter before the encrypted payload. Everything is
/// encrypted, so we report the message type and, for data packets, the receiver
/// index — enough to see a tunnel come up and carry traffic.
pub fn dissect_wireguard(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let result = |summary: String| DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::WireGuard,
        summary,
    };

    if payload.len() < 4 {
        return result("WireGuard (partial)".into());
    }

    let summary = match payload[0] {
        1 => "WireGuard Handshake Initiation".to_string(),
        2 => "WireGuard Handshake Response".to_string(),
        3 => "WireGuard Cookie Reply".to_string(),
        4 => {
            // The receiver index sits at bytes 4..8 for transport-data packets.
            let receiver = if payload.len() >= 8 {
                u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]])
            } else {
                0
            };
            format!("WireGuard Transport Data — receiver 0x{receiver:08x}")
        }
        _ => return result("WireGuard (unrecognized type)".into()),
    };

    result(summary)
}

/// Whether a UDP payload looks like WireGuard: a valid message type (1..=4) with
/// the three reserved bytes zeroed. Strict enough to accept on relocated ports.
pub fn looks_like_wireguard(payload: &[u8]) -> bool {
    payload.len() >= 4
        && (1..=4).contains(&payload[0])
        && payload[1] == 0
        && payload[2] == 0
        && payload[3] == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_initiation() {
        let mut p = vec![1, 0, 0, 0];
        p.extend_from_slice(&[0u8; 144]);
        let r = dissect_wireguard(None, None, 50000, 51820, &p);
        assert_eq!(r.protocol, Protocol::WireGuard);
        assert_eq!(r.summary, "WireGuard Handshake Initiation");
    }

    #[test]
    fn transport_data() {
        let mut p = vec![4, 0, 0, 0];
        p.extend_from_slice(&0x0a0b0c0du32.to_le_bytes()); // receiver index
        p.extend_from_slice(&[0u8; 8]); // counter
        let r = dissect_wireguard(None, None, 51820, 50000, &p);
        assert_eq!(r.summary, "WireGuard Transport Data — receiver 0x0a0b0c0d");
    }

    #[test]
    fn detection() {
        assert!(looks_like_wireguard(&[2, 0, 0, 0, 0, 0]));
        assert!(!looks_like_wireguard(&[2, 1, 0, 0]));
        assert!(!looks_like_wireguard(&[9, 0, 0, 0]));
    }
}
