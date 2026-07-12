use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an OpenVPN packet (UDP/TCP 1194).
///
/// OpenVPN multiplexes a TLS control channel and an encrypted data channel over
/// one port. The first byte packs the opcode in its high 5 bits and a key id in
/// the low 3. Control packets (hard-reset, control-v1, ack) set up and rekey the
/// tunnel; data packets carry the encrypted payload. Over TCP a 2-byte length
/// prefixes each packet. We name the packet type and key id — enough to spot a
/// VPN handshake and tell control from bulk data.
pub fn dissect_openvpn(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    is_tcp: bool,
) -> DissectedResult {
    let result = |summary: String| DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::OpenVpn,
        summary,
    };

    // TCP framing prefixes a 2-byte length; the opcode byte follows it.
    let op_byte = if is_tcp {
        payload.get(2)
    } else {
        payload.first()
    };
    let Some(&b) = op_byte else {
        return result("OpenVPN (partial)".into());
    };

    let opcode = b >> 3;
    let key_id = b & 0x07;
    let name = opcode_name(opcode);
    result(format!("OpenVPN {name} (key {key_id})"))
}

fn opcode_name(op: u8) -> &'static str {
    match op {
        1 => "P_CONTROL_HARD_RESET_CLIENT_V1",
        2 => "P_CONTROL_HARD_RESET_SERVER_V1",
        3 => "P_CONTROL_SOFT_RESET_V1",
        4 => "P_CONTROL_V1",
        5 => "P_ACK_V1",
        6 => "P_DATA_V1",
        7 => "P_CONTROL_HARD_RESET_CLIENT_V2",
        8 => "P_CONTROL_HARD_RESET_SERVER_V2",
        9 => "P_DATA_V2",
        10 => "P_CONTROL_HARD_RESET_CLIENT_V3",
        11 => "P_CONTROL_WKC_V1",
        _ => "packet",
    }
}

/// Whether a UDP payload's opcode byte is a valid OpenVPN opcode (1..=11). Used
/// to accept OpenVPN on relocated ports.
pub fn looks_like_openvpn(payload: &[u8]) -> bool {
    match payload.first() {
        Some(&b) => (1..=11).contains(&(b >> 3)),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hard_reset_client_v2_udp() {
        // opcode 7 << 3 | key 0 = 0x38
        let r = dissect_openvpn(None, None, 50000, 1194, &[0x38, 0, 0], false);
        assert_eq!(r.protocol, Protocol::OpenVpn);
        assert_eq!(r.summary, "OpenVPN P_CONTROL_HARD_RESET_CLIENT_V2 (key 0)");
    }

    #[test]
    fn data_v2_udp() {
        // opcode 9 << 3 | key 1 = 0x49
        let r = dissect_openvpn(None, None, 1194, 50000, &[0x49, 0, 0], false);
        assert_eq!(r.summary, "OpenVPN P_DATA_V2 (key 1)");
    }

    #[test]
    fn control_v1_tcp_prefixed() {
        // 2-byte length, then opcode 4 << 3 = 0x20
        let r = dissect_openvpn(None, None, 50000, 1194, &[0x00, 0x2a, 0x20], true);
        assert_eq!(r.summary, "OpenVPN P_CONTROL_V1 (key 0)");
    }

    #[test]
    fn detection() {
        assert!(looks_like_openvpn(&[0x38]));
        assert!(!looks_like_openvpn(&[0xf0]));
    }
}
