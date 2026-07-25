use std::net::IpAddr;
use crate::models::Protocol;
use super::DissectedResult;

pub fn dissect_tsn_stream_reservation(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    let summary = if payload.len() < 8 {
        "TSN Stream Reservation (malformed)".into()
    } else {
        let raw = String::from_utf8_lossy(payload);
        if raw.contains("SRP") || raw.contains("StreamReserve") || raw.contains("talker") {
            let end = raw.len().min(80);
            format!("TSN Stream Reservation: {}", &raw[..end])
        } else if raw.contains("listener") || raw.contains("accumulated_latency") {
            format!("TSN Stream Reservation: {}", &raw[..raw.len().min(80)])
        } else {
            format!("TSN Stream Reservation ({})", super::bytes(payload.len() as u64))
        }
    };
    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::TsnStreamReservation,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tsn_stream_reservation_srp() {
        let buf = b"SRP:talker:StreamReserve:accumulated_latency=100us";
        let r = dissect_tsn_stream_reservation(None, None, 0, 0, buf);
        assert_eq!(r.protocol, Protocol::TsnStreamReservation);
        assert!(r.summary.contains("SRP"));
    }

    #[test]
    fn test_tsn_stream_reservation_malformed() {
        let buf = b"short";
        let r = dissect_tsn_stream_reservation(None, None, 0, 0, buf);
        assert!(r.summary.contains("malformed"));
    }
}
