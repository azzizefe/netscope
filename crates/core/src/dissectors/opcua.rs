use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an OPC UA binary message (TCP 4840).
///
/// OPC UA is the backbone of Industry 4.0 / IIoT data exchange. Its TCP mapping
/// prefixes every message with an 8-byte header: a 3-byte ASCII message type
/// ("HEL", "ACK", "OPN", "MSG", "CLO", "ERR"), a 1-byte chunk type ('F' final,
/// 'C' intermediate, 'A' abort), and a 4-byte little-endian size. We name the
/// message type — the Hello/Acknowledge handshake, secure-channel open, and
/// the MSG frames that carry the actual service calls.
pub fn dissect_opcua(
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
        protocol: Protocol::OpcUa,
        summary,
    };

    if payload.len() < 8 {
        return result("OPC UA (partial)".into());
    }

    let msg_type = &payload[0..3];
    let chunk = payload[3];
    let name = match msg_type {
        b"HEL" => "Hello",
        b"ACK" => "Acknowledge",
        b"ERR" => "Error",
        b"RHE" => "ReverseHello",
        b"OPN" => "OpenSecureChannel",
        b"CLO" => "CloseSecureChannel",
        b"MSG" => "Message",
        _ => return result("OPC UA (unrecognized)".into()),
    };

    let summary = match chunk {
        b'C' => format!("OPC UA {name} (intermediate chunk)"),
        b'A' => format!("OPC UA {name} (abort)"),
        _ => format!("OPC UA {name}"),
    };
    result(summary)
}

/// Whether a payload begins with a recognised OPC UA message type and a valid
/// chunk-type byte — enough to accept it on a non-standard port.
pub fn looks_like_opcua(payload: &[u8]) -> bool {
    payload.len() >= 8
        && matches!(
            &payload[0..3],
            b"HEL" | b"ACK" | b"ERR" | b"RHE" | b"OPN" | b"CLO" | b"MSG"
        )
        && matches!(payload[3], b'F' | b'C' | b'A')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(kind: &[u8; 3], chunk: u8) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(kind);
        p.push(chunk);
        p.extend_from_slice(&28u32.to_le_bytes());
        p
    }

    #[test]
    fn hello() {
        let p = msg(b"HEL", b'F');
        let r = dissect_opcua(None, None, 50000, 4840, &p);
        assert_eq!(r.protocol, Protocol::OpcUa);
        assert_eq!(r.summary, "OPC UA Hello");
    }

    #[test]
    fn open_secure_channel() {
        let p = msg(b"OPN", b'F');
        let r = dissect_opcua(None, None, 50000, 4840, &p);
        assert_eq!(r.summary, "OPC UA OpenSecureChannel");
    }

    #[test]
    fn detection() {
        assert!(looks_like_opcua(&msg(b"MSG", b'F')));
        assert!(!looks_like_opcua(b"GET / HT"));
    }
}
