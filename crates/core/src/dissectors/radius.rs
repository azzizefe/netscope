use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a RADIUS message (UDP 1812/1813, legacy 1645/1646).
///
/// RADIUS authenticates and accounts network access — Wi-Fi logins, VPN, 802.1X.
/// The header is fixed: code(1), identifier(1), length(2), then a 16-byte
/// authenticator and TLV attributes. The code names the exchange
/// (Access-Request → Access-Accept/Reject/Challenge; Accounting-Request →
/// Response). We surface the code and the id that pairs a request with its reply.
pub fn dissect_radius(
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
        protocol: Protocol::Radius,
        summary,
    };

    if payload.len() < 20 {
        return result("RADIUS (partial)".into());
    }

    let code = payload[0];
    let id = payload[1];
    result(format!("RADIUS {} (id {id})", code_name(code)))
}

fn code_name(code: u8) -> &'static str {
    match code {
        1 => "Access-Request",
        2 => "Access-Accept",
        3 => "Access-Reject",
        4 => "Accounting-Request",
        5 => "Accounting-Response",
        11 => "Access-Challenge",
        12 => "Status-Server",
        13 => "Status-Client",
        40 => "Disconnect-Request",
        41 => "Disconnect-ACK",
        42 => "Disconnect-NAK",
        43 => "CoA-Request",
        44 => "CoA-ACK",
        45 => "CoA-NAK",
        _ => "message",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(code: u8, id: u8) -> Vec<u8> {
        let mut p = vec![code, id, 0x00, 0x14];
        p.extend_from_slice(&[0u8; 16]); // authenticator
        p
    }

    #[test]
    fn access_request() {
        let r = dissect_radius(None, None, 50000, 1812, &packet(1, 7));
        assert_eq!(r.protocol, Protocol::Radius);
        assert_eq!(r.summary, "RADIUS Access-Request (id 7)");
    }

    #[test]
    fn access_accept() {
        let r = dissect_radius(None, None, 1812, 50000, &packet(2, 7));
        assert_eq!(r.summary, "RADIUS Access-Accept (id 7)");
    }

    #[test]
    fn partial_is_safe() {
        let r = dissect_radius(None, None, 1812, 50000, &[1, 2, 3]);
        assert!(r.summary.contains("partial"));
    }
}
