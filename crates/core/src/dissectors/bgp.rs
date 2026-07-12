use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect a BGP message (TCP 179).
///
/// BGP is the protocol that glues the internet's networks together — it's how
/// autonomous systems tell each other which IP prefixes they can reach. Each
/// message starts with a 19-byte header: a 16-byte marker (all ones), a 2-byte
/// length, and a type. OPEN sets up a session, UPDATE advertises or withdraws
/// routes, KEEPALIVE holds it open, NOTIFICATION tears it down on error. We name
/// the message and, for OPEN, surface the advertised AS number.
pub fn dissect_bgp(
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
        protocol: Protocol::Bgp,
        summary,
    };

    if payload.len() < 19 {
        return result("BGP (partial)".into());
    }

    let msg_type = payload[18];
    let summary = match msg_type {
        1 => {
            // OPEN: version(1), my-AS(2), hold-time(2), BGP-id(4)...
            let my_as = u16::from_be_bytes([payload[20], payload[21]]);
            format!("BGP OPEN — AS {my_as}")
        }
        2 => "BGP UPDATE".to_string(),
        3 => {
            let (code, subcode) = (payload.get(19).copied(), payload.get(20).copied());
            match (code, subcode) {
                (Some(c), Some(s)) => format!("BGP NOTIFICATION — error {c}/{s}"),
                _ => "BGP NOTIFICATION".to_string(),
            }
        }
        4 => "BGP KEEPALIVE".to_string(),
        5 => "BGP ROUTE-REFRESH".to_string(),
        other => format!("BGP message type {other}"),
    };
    result(summary)
}

/// Whether a TCP payload looks like BGP: the 16-byte all-ones marker and a
/// sane length/type. Lets BGP be recognised even off port 179.
pub fn looks_like_bgp(payload: &[u8]) -> bool {
    payload.len() >= 19
        && payload[..16].iter().all(|&b| b == 0xff)
        && (1..=5).contains(&payload[18])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(msg_type: u8, extra: &[u8]) -> Vec<u8> {
        let mut p = vec![0xff; 16];
        let len = (19 + extra.len()) as u16;
        p.extend_from_slice(&len.to_be_bytes());
        p.push(msg_type);
        p.extend_from_slice(extra);
        p
    }

    #[test]
    fn keepalive() {
        let r = dissect_bgp(None, None, 50000, 179, &header(4, &[]));
        assert_eq!(r.protocol, Protocol::Bgp);
        assert_eq!(r.summary, "BGP KEEPALIVE");
    }

    #[test]
    fn open_shows_as() {
        // version, my-AS = 65001, ...
        let mut extra = vec![4];
        extra.extend_from_slice(&65001u16.to_be_bytes());
        extra.extend_from_slice(&[0, 180, 1, 2, 3, 4, 0]);
        let r = dissect_bgp(None, None, 179, 50000, &header(1, &extra));
        assert_eq!(r.summary, "BGP OPEN — AS 65001");
    }

    #[test]
    fn detection() {
        assert!(looks_like_bgp(&header(2, &[])));
        assert!(!looks_like_bgp(&[0u8; 19]));
    }
}
