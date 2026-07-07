use std::net::IpAddr;

use crate::models::Protocol;

use super::DissectedResult;

/// Dissect an RDP segment (TCP 3389). RDP rides on a TPKT framing layer whose
/// first byte is the version (0x03); the connection is otherwise encrypted, so
/// we identify it and note the initial connection request when we can see it.
pub fn dissect_rdp(
    src_ip: Option<IpAddr>,
    dst_ip: Option<IpAddr>,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> DissectedResult {
    // A TPKT header starts with version 3, reserved 0.
    let is_tpkt = payload.first() == Some(&0x03) && payload.get(1) == Some(&0x00);
    // The very first PDU on an RDP connection is an X.224 Connection Request,
    // recognisable by the CR TPDU code (0xE0) in the X.224 header.
    let is_connection_request = is_tpkt && payload.get(5) == Some(&0xE0);

    let summary = if is_connection_request {
        "RDP — connection request (Remote Desktop)".into()
    } else {
        "RDP (Remote Desktop)".into()
    };

    DissectedResult {
        src_addr: src_ip,
        dst_addr: dst_ip,
        src_port: Some(src_port),
        dst_port: Some(dst_port),
        protocol: Protocol::Rdp,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_request_detected() {
        // TPKT (03 00 00 2c) + X.224 length (22) + CR code (E0) …
        let pkt = [0x03, 0x00, 0x00, 0x2c, 0x17, 0xE0, 0x00, 0x00];
        let r = dissect_rdp(None, None, 50000, 3389, &pkt);
        assert_eq!(r.protocol, Protocol::Rdp);
        assert!(r.summary.contains("connection request"));
    }

    #[test]
    fn generic_rdp_traffic() {
        let r = dissect_rdp(None, None, 3389, 50000, &[0x30, 0x00, 0x01]);
        assert_eq!(r.summary, "RDP (Remote Desktop)");
    }
}
